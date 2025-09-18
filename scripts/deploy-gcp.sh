#!/bin/bash

# GCP Deployment Script for Vulnerable Web Application
# This script automates the deployment process to Google Cloud Platform

set -e

# Configuration
PROJECT_ID=""
REGION="us-central1"
BACKEND_SERVICE="vulnerable-webapp-backend"
FRONTEND_SERVICE="vulnerable-webapp-frontend"
DB_INSTANCE="vulnerable-webapp-db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 GCP Deployment Script for Vulnerable Web Application${NC}"
echo "=================================================="

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ Google Cloud CLI is not installed${NC}"
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Check if user is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
    echo -e "${YELLOW}⚠️  Please authenticate with Google Cloud${NC}"
    gcloud auth login
fi

# Get or set project ID
if [ -z "$PROJECT_ID" ]; then
    echo -e "${BLUE}📋 Enter your GCP Project ID:${NC}"
    read -r PROJECT_ID
fi

echo -e "${BLUE}Setting project to: ${PROJECT_ID}${NC}"
gcloud config set project "$PROJECT_ID"

# Enable required APIs
echo -e "${BLUE}🔧 Enabling required APIs...${NC}"
gcloud services enable run.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Deploy backend
echo -e "${BLUE}🐳 Deploying backend to Cloud Run...${NC}"
gcloud run deploy "$BACKEND_SERVICE" \
  --source ./backend \
  --platform managed \
  --region "$REGION" \
  --allow-unauthenticated \
  --memory 1Gi \
  --cpu 1 \
  --max-instances 10 \
  --timeout 300

# Get backend URL
BACKEND_URL=$(gcloud run services describe "$BACKEND_SERVICE" --region="$REGION" --format="value(status.url)")
echo -e "${GREEN}✅ Backend deployed: $BACKEND_URL${NC}"

# Deploy frontend
echo -e "${BLUE}🌐 Deploying frontend to Cloud Run...${NC}"
gcloud run deploy "$FRONTEND_SERVICE" \
  --source ./frontend \
  --platform managed \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-env-vars "VITE_API_URL=$BACKEND_URL" \
  --memory 512Mi \
  --cpu 1 \
  --max-instances 5 \
  --timeout 300

# Get frontend URL
FRONTEND_URL=$(gcloud run services describe "$FRONTEND_SERVICE" --region="$REGION" --format="value(status.url)")
echo -e "${GREEN}✅ Frontend deployed: $FRONTEND_URL${NC}"

echo ""
echo -e "${GREEN}🎉 Deployment Complete!${NC}"
echo "=================================================="
echo -e "${BLUE}Frontend URL:${NC} $FRONTEND_URL"
echo -e "${BLUE}Backend URL:${NC} $BACKEND_URL"
echo ""
echo -e "${YELLOW}⚠️  Note: You still need to set up the database manually${NC}"
echo "1. Create a Cloud SQL PostgreSQL instance"
echo "2. Update the backend environment variables with database connection details"
echo "3. Run database migrations"
echo ""
echo -e "${BLUE}📚 For detailed instructions, see: docs/GCP_DEPLOYMENT_GUIDE.md${NC}"
