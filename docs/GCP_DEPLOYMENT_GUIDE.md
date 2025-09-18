# 🚀 GCP Deployment Guide - Manual Steps

## Overview
This guide will walk you through deploying your vulnerable web application to Google Cloud Platform using Cloud Run (serverless) and Cloud SQL.

## 📋 Prerequisites

### 1. Google Cloud Account
- Create a Google Cloud account at https://cloud.google.com/
- Set up billing (required for Cloud Run and Cloud SQL)

### 2. Google Cloud CLI Installation
Download and install from: https://cloud.google.com/sdk/docs/install

### 3. Verify Installation
```bash
gcloud --version
gcloud auth login
```

## 🏗️ Step 1: Create GCP Project

### Option A: Using Google Cloud Console
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click "Select a project" → "New Project"
3. Project name: `vulnerable-webapp-lab`
4. Click "Create"

### Option B: Using CLI
```bash
gcloud projects create vulnerable-webapp-lab --name="Vulnerable Web App Lab"
gcloud config set project vulnerable-webapp-lab
```

## 🔧 Step 2: Enable Required APIs

### Enable APIs via Console
1. Go to "APIs & Services" → "Library"
2. Enable these APIs:
   - Cloud Run API
   - Cloud SQL Admin API
   - Cloud Build API
   - Container Registry API

### Enable APIs via CLI
```bash
gcloud services enable run.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable containerregistry.googleapis.com
```

## 🗄️ Step 3: Set Up Cloud SQL Database

### Create PostgreSQL Instance
1. Go to "SQL" in the Cloud Console
2. Click "Create Instance"
3. Choose "PostgreSQL"
4. Configure:
   - **Instance ID**: `vulnerable-webapp-db`
   - **Password**: Create a strong password
   - **Region**: Choose closest to your users
   - **Machine type**: `db-f1-micro` (for testing)
   - **Storage**: 10GB SSD
5. Click "Create"

### Create Database and User
```sql
-- Connect to your instance and run:
CREATE DATABASE vulnerable_webapp;
CREATE USER webapp_user WITH PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE vulnerable_webapp TO webapp_user;
```

### Get Connection Details
1. Note down your instance connection name (format: `project:region:instance`)
2. Note down the public IP address

## 🐳 Step 4: Prepare for Cloud Run Deployment

### Create Environment File
Create `.env.production` file:
```env
# Database Configuration
POSTGRES_DB=vulnerable_webapp
POSTGRES_USER=webapp_user
POSTGRES_PASSWORD=your-secure-password
DATABASE_URL=postgresql://webapp_user:your-secure-password@your-db-ip:5432/vulnerable_webapp

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_REFRESH_SECRET=your-super-secret-refresh-key-here

# Application Configuration
NODE_ENV=production
PORT=3001
CORS_ORIGIN=https://your-app-url.run.app

# Security Configuration
UPLOAD_MAX_SIZE=10485760
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
```

## 🚀 Step 5: Deploy Backend to Cloud Run

### Method 1: Using Cloud Build (Recommended)
1. Go to "Cloud Build" → "Triggers"
2. Click "Create Trigger"
3. Connect your GitHub repository
4. Configuration:
   - **Name**: `vulnerable-webapp-backend`
   - **Source**: Select your repository
   - **Branch**: `main`
   - **Build Configuration**: Cloud Build configuration file
   - **Location**: `backend/cloudbuild.yaml`

### Create Cloud Build Configuration
Create `backend/cloudbuild.yaml`:
```yaml
steps:
  # Build the container image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/vulnerable-webapp-backend', './backend']
  
  # Push the container image to Container Registry
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/vulnerable-webapp-backend']
  
  # Deploy container image to Cloud Run
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
    - 'run'
    - 'deploy'
    - 'vulnerable-webapp-backend'
    - '--image'
    - 'gcr.io/$PROJECT_ID/vulnerable-webapp-backend'
    - '--region'
    - 'us-central1'
    - '--platform'
    - 'managed'
    - '--allow-unauthenticated'
    - '--set-env-vars'
    - 'NODE_ENV=production,DATABASE_URL=postgresql://webapp_user:password@your-db-ip:5432/vulnerable_webapp,JWT_SECRET=your-jwt-secret'
    - '--memory'
    - '1Gi'
    - '--cpu'
    - '1'
    - '--max-instances'
    - '10'

images:
  - 'gcr.io/$PROJECT_ID/vulnerable-webapp-backend'
```

### Method 2: Manual Deployment
```bash
# Build and deploy backend
gcloud run deploy vulnerable-webapp-backend \
  --source ./backend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars NODE_ENV=production,DATABASE_URL=postgresql://webapp_user:password@your-db-ip:5432/vulnerable_webapp,JWT_SECRET=your-jwt-secret \
  --memory 1Gi \
  --cpu 1 \
  --max-instances 10
```

## 🌐 Step 6: Deploy Frontend to Cloud Run

### Create Frontend Cloud Build Configuration
Create `frontend/cloudbuild.yaml`:
```yaml
steps:
  # Build the container image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/$PROJECT_ID/vulnerable-webapp-frontend', './frontend']
  
  # Push the container image to Container Registry
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'gcr.io/$PROJECT_ID/vulnerable-webapp-frontend']
  
  # Deploy container image to Cloud Run
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
    - 'run'
    - 'deploy'
    - 'vulnerable-webapp-frontend'
    - '--image'
    - 'gcr.io/$PROJECT_ID/vulnerable-webapp-frontend'
    - '--region'
    - 'us-central1'
    - '--platform'
    - 'managed'
    - '--allow-unauthenticated'
    - '--set-env-vars'
    - 'VITE_API_URL=https://vulnerable-webapp-backend-url.run.app'
    - '--memory'
    - '512Mi'
    - '--cpu'
    - '1'
    - '--max-instances'
    - '5'

images:
  - 'gcr.io/$PROJECT_ID/vulnerable-webapp-frontend'
```

### Deploy Frontend
```bash
# Build and deploy frontend
gcloud run deploy vulnerable-webapp-frontend \
  --source ./frontend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars VITE_API_URL=https://your-backend-url.run.app \
  --memory 512Mi \
  --cpu 1 \
  --max-instances 5
```

## 🔒 Step 7: Configure Database Connection

### Update Cloud SQL Instance
1. Go to "SQL" → Your instance
2. Click "Connections"
3. Add authorized networks (for Cloud Run):
   - `0.0.0.0/0` (for testing - restrict in production)
4. Or use Cloud SQL Proxy for secure connection

### Using Cloud SQL Proxy (Recommended)
```bash
# Add Cloud SQL Proxy to your backend deployment
gcloud run deploy vulnerable-webapp-backend \
  --image gcr.io/$PROJECT_ID/vulnerable-webapp-backend \
  --add-cloudsql-instances $PROJECT_ID:us-central1:vulnerable-webapp-db \
  --set-env-vars CLOUD_SQL_CONNECTION_NAME=$PROJECT_ID:us-central1:vulnerable-webapp-db
```

## 🌍 Step 8: Custom Domain Setup (Optional)

### Map Custom Domain
1. Go to "Cloud Run" → Select your service
2. Click "Manage Custom Domains"
3. Add your domain
4. Follow DNS configuration instructions

### SSL Certificate
```bash
# Create SSL certificate
gcloud compute ssl-certificates create vulnerable-webapp-ssl \
  --domains yourdomain.com,www.yourdomain.com \
  --global
```

## 📊 Step 9: Monitoring and Logging

### Enable Cloud Monitoring
1. Go to "Monitoring" in Cloud Console
2. Create dashboards for:
   - Request metrics
   - Error rates
   - Response times
   - Database connections

### Set Up Alerts
1. Go to "Monitoring" → "Alerting"
2. Create alerting policies for:
   - High error rates
   - Slow response times
   - Database connection issues

## 🔧 Step 10: Security Configuration

### Environment Variables
Set these in Cloud Run:
```bash
# Security headers
SECURE_HEADERS=true
CORS_ORIGIN=https://your-frontend-url.run.app

# Rate limiting
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100

# Upload limits
UPLOAD_MAX_SIZE=10485760
```

### IAM Permissions
```bash
# Create service account
gcloud iam service-accounts create vulnerable-webapp-sa \
  --display-name="Vulnerable Web App Service Account"

# Grant necessary permissions
gcloud projects add-iam-policy-binding $PROJECT_ID \
  --member="serviceAccount:vulnerable-webapp-sa@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudsql.client"
```

## 🧪 Step 11: Testing Your Deployment

### Test Backend
```bash
# Get your backend URL
BACKEND_URL=$(gcloud run services describe vulnerable-webapp-backend --region=us-central1 --format="value(status.url)")

# Test health endpoint
curl $BACKEND_URL/health

# Test API endpoints
curl $BACKEND_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","firstName":"Test","lastName":"User"}'
```

### Test Frontend
```bash
# Get your frontend URL
FRONTEND_URL=$(gcloud run services describe vulnerable-webapp-frontend --region=us-central1 --format="value(status.url)")

# Open in browser
echo "Frontend URL: $FRONTEND_URL"
```

## 💰 Cost Optimization

### Cloud Run Settings
- **CPU allocation**: Only during request processing
- **Concurrency**: 1000 requests per instance
- **Min instances**: 0 (scales to zero)
- **Max instances**: 10 (adjust based on traffic)

### Cloud SQL Settings
- **Machine type**: `db-f1-micro` for testing
- **Storage**: Start with 10GB, auto-increase
- **Backup**: Enable automated backups

## 🚨 Important Security Notes

### For Production Use
1. **Restrict database access** to Cloud Run instances only
2. **Use strong secrets** for JWT and database passwords
3. **Enable VPC** for network isolation
4. **Set up proper IAM** roles and permissions
5. **Enable audit logging**
6. **Use Cloud Armor** for DDoS protection

### For Educational Use
- The vulnerabilities are intentional for learning
- Use only in isolated environments
- Don't expose to public internet without restrictions

## 📝 Deployment Checklist

- [ ] GCP project created
- [ ] Required APIs enabled
- [ ] Cloud SQL instance created
- [ ] Database and user created
- [ ] Backend deployed to Cloud Run
- [ ] Frontend deployed to Cloud Run
- [ ] Environment variables configured
- [ ] Database connection tested
- [ ] Custom domain configured (optional)
- [ ] SSL certificate installed (optional)
- [ ] Monitoring enabled
- [ ] Alerts configured
- [ ] Security settings applied

## 🆘 Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check Cloud SQL instance is running
   - Verify connection string format
   - Ensure authorized networks are configured

2. **Build Failures**
   - Check Dockerfile syntax
   - Verify all dependencies are included
   - Check build logs in Cloud Build

3. **Environment Variables Not Working**
   - Verify variable names match code
   - Check for typos in values
   - Ensure variables are set in Cloud Run

4. **CORS Errors**
   - Update CORS_ORIGIN with correct frontend URL
   - Check frontend API_URL configuration

### Getting Help
- Check Cloud Run logs: `gcloud logs read`
- Check Cloud Build logs in Console
- Review Cloud SQL connection logs
- Use Cloud Console debugging tools

## 🎯 Next Steps

After successful deployment:
1. **Test all functionality** in the deployed environment
2. **Set up CI/CD** for automated deployments
3. **Configure monitoring** and alerting
4. **Document your deployment** process
5. **Share with the security community**

Your vulnerable web application is now running on Google Cloud Platform! 🎉
