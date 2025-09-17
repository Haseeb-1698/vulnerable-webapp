# 🚀 Deployment Guide

## GCP Deployment Options

### Option 1: Google Cloud Run (Recommended)
Perfect for containerized applications with automatic scaling.

#### Prerequisites
```bash
# Install Google Cloud CLI
# https://cloud.google.com/sdk/docs/install

# Authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com
```

#### Deploy to Cloud Run
```bash
# Build and deploy backend
gcloud run deploy vulnerable-webapp-backend \
  --source ./backend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars NODE_ENV=production \
  --set-env-vars JWT_SECRET=your-secret-key \
  --memory 1Gi \
  --cpu 1 \
  --max-instances 10

# Build and deploy frontend
gcloud run deploy vulnerable-webapp-frontend \
  --source ./frontend \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars VITE_API_URL=https://vulnerable-webapp-backend-url \
  --memory 512Mi \
  --cpu 1 \
  --max-instances 5
```

#### Database Setup (Cloud SQL)
```bash
# Create Cloud SQL instance
gcloud sql instances create vulnerable-webapp-db \
  --database-version POSTGRES_14 \
  --tier db-f1-micro \
  --region us-central1 \
  --storage-type SSD \
  --storage-size 10GB

# Create database
gcloud sql databases create vulnerable_webapp --instance vulnerable-webapp-db

# Create user
gcloud sql users create webapp_user --instance vulnerable-webapp-db --password your_password
```

### Option 2: Google Kubernetes Engine (GKE)
For more control and enterprise features.

#### Create GKE Cluster
```bash
# Create cluster
gcloud container clusters create vulnerable-webapp-cluster \
  --num-nodes 3 \
  --machine-type e2-medium \
  --region us-central1 \
  --enable-autoscaling \
  --min-nodes 1 \
  --max-nodes 10

# Get credentials
gcloud container clusters get-credentials vulnerable-webapp-cluster --region us-central1
```

#### Deploy with Kubernetes
```bash
# Apply configurations
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/postgres.yaml
kubectl apply -f k8s/backend.yaml
kubectl apply -f k8s/frontend.yaml
kubectl apply -f k8s/ingress.yaml
```

### Option 3: Compute Engine with Docker
For traditional VM deployment.

#### Create VM with Docker
```bash
# Create VM
gcloud compute instances create vulnerable-webapp-vm \
  --image-family cos-stable \
  --image-project cos-cloud \
  --machine-type e2-medium \
  --zone us-central1-a \
  --tags http-server,https-server \
  --metadata-from-file startup-script=scripts/gcp-startup.sh
```

## 🐳 Docker Deployment Commands

### Local Development
```bash
# Start development environment
.\scripts\deploy.ps1 -Environment development -EnableMonitoring

# Or with Docker Compose directly
docker-compose up -d
```

### Production Deployment
```bash
# Start production environment
.\scripts\deploy.ps1 -Environment production -EnableMonitoring -RunSecurityScan

# Or with Docker Compose
docker-compose -f docker-compose.prod.yml up -d
```

### Security-Hardened Deployment
```bash
# Start hardened environment
.\scripts\deploy.ps1 -Environment hardened -EnableMonitoring -RunSecurityScan
```

## 📊 Monitoring & Logging

### Application URLs
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:3001/api
- **Health Check**: http://localhost:3001/health
- **Monitoring Dashboard**: http://localhost:3000/monitoring
- **Security Logs**: http://localhost:3000/logs

### Docker Commands
```bash
# View logs
docker-compose logs -f

# View specific service logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Execute commands in containers
docker-compose exec backend npm run db:migrate
docker-compose exec backend npm run db:seed

# Scale services
docker-compose up -d --scale backend=3

# Update services
docker-compose pull
docker-compose up -d
```

## 🔒 Security Considerations

### Environment Variables
Create `.env.production` file:
```env
# Database
POSTGRES_DB=vulnerable_webapp
POSTGRES_USER=webapp_user
POSTGRES_PASSWORD=your_secure_password

# JWT Secrets (Generate strong secrets)
JWT_SECRET=your-super-secret-jwt-key
JWT_REFRESH_SECRET=your-super-secret-refresh-key

# CORS
CORS_ORIGIN=https://yourdomain.com

# Upload limits
UPLOAD_MAX_SIZE=10485760
RATE_LIMIT_WINDOW=900000
RATE_LIMIT_MAX=100
```

### Security Scanning
```bash
# Run security scan
.\scripts\security-scan.ps1

# Skip build if containers exist
.\scripts\security-scan.ps1 -SkipBuild
```

## 🌐 Domain & SSL Setup

### Custom Domain (Cloud Run)
```bash
# Map domain
gcloud run domain-mappings create \
  --service vulnerable-webapp-frontend \
  --domain yourdomain.com \
  --region us-central1
```

### SSL Certificates
```bash
# Create SSL certificate
gcloud compute ssl-certificates create vulnerable-webapp-ssl \
  --domains yourdomain.com,www.yourdomain.com \
  --global
```

## 📈 Scaling & Performance

### Auto-scaling (Cloud Run)
- Automatic scaling based on traffic
- Cold start optimization
- Memory and CPU allocation per service

### Load Balancing (GKE)
- Horizontal Pod Autoscaler
- Cluster Autoscaler
- Network Load Balancer

## 🔧 Troubleshooting

### Common Issues
1. **Database Connection**: Check DATABASE_URL environment variable
2. **CORS Errors**: Verify CORS_ORIGIN setting
3. **Port Conflicts**: Check if ports 3000/3001 are available
4. **Permission Issues**: Ensure Docker has proper permissions

### Debug Commands
```bash
# Check container status
docker-compose ps

# Inspect container
docker-compose exec backend sh

# View resource usage
docker stats

# Check logs
docker-compose logs --tail=100 backend
```

## 📝 Environment-Specific Configurations

### Development
- Hot reload enabled
- Debug logging
- Local database
- CORS allows localhost

### Production
- Optimized builds
- Security hardening
- Production database
- Restricted CORS
- SSL/HTTPS

### Hardened
- Maximum security controls
- Read-only containers
- Resource limits
- Comprehensive monitoring
