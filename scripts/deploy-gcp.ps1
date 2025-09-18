# GCP Deployment Script for Vulnerable Web Application (PowerShell)
# This script automates the deployment process to Google Cloud Platform

param(
    [Parameter(Mandatory=$false)]
    [string]$ProjectId = "",
    
    [Parameter(Mandatory=$false)]
    [string]$Region = "us-central1"
)

# Configuration
$BackendService = "vulnerable-webapp-backend"
$FrontendService = "vulnerable-webapp-frontend"
$DbInstance = "vulnerable-webapp-db"

Write-Host "🚀 GCP Deployment Script for Vulnerable Web Application" -ForegroundColor Blue
Write-Host "==================================================" -ForegroundColor Blue

# Check if gcloud is installed
try {
    gcloud --version | Out-Null
    Write-Host "✅ Google Cloud CLI found" -ForegroundColor Green
} catch {
    Write-Host "❌ Google Cloud CLI is not installed" -ForegroundColor Red
    Write-Host "Please install it from: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    exit 1
}

# Check if user is authenticated
try {
    $activeAccount = gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>$null
    if (-not $activeAccount) {
        Write-Host "⚠️  Please authenticate with Google Cloud" -ForegroundColor Yellow
        gcloud auth login
    }
} catch {
    Write-Host "⚠️  Please authenticate with Google Cloud" -ForegroundColor Yellow
    gcloud auth login
}

# Get or set project ID
if (-not $ProjectId) {
    $ProjectId = Read-Host "📋 Enter your GCP Project ID"
}

Write-Host "Setting project to: $ProjectId" -ForegroundColor Blue
gcloud config set project $ProjectId

# Enable required APIs
Write-Host "🔧 Enabling required APIs..." -ForegroundColor Blue
gcloud services enable run.googleapis.com
gcloud services enable sqladmin.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable containerregistry.googleapis.com

# Deploy backend
Write-Host "🐳 Deploying backend to Cloud Run..." -ForegroundColor Blue
gcloud run deploy $BackendService `
  --source ./backend `
  --platform managed `
  --region $Region `
  --allow-unauthenticated `
  --memory 1Gi `
  --cpu 1 `
  --max-instances 10 `
  --timeout 300

# Get backend URL
$BackendUrl = gcloud run services describe $BackendService --region=$Region --format="value(status.url)"
Write-Host "✅ Backend deployed: $BackendUrl" -ForegroundColor Green

# Deploy frontend
Write-Host "🌐 Deploying frontend to Cloud Run..." -ForegroundColor Blue
gcloud run deploy $FrontendService `
  --source ./frontend `
  --platform managed `
  --region $Region `
  --allow-unauthenticated `
  --set-env-vars "VITE_API_URL=$BackendUrl" `
  --memory 512Mi `
  --cpu 1 `
  --max-instances 5 `
  --timeout 300

# Get frontend URL
$FrontendUrl = gcloud run services describe $FrontendService --region=$Region --format="value(status.url)"
Write-Host "✅ Frontend deployed: $FrontendUrl" -ForegroundColor Green

Write-Host ""
Write-Host "🎉 Deployment Complete!" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Blue
Write-Host "Frontend URL: $FrontendUrl" -ForegroundColor Blue
Write-Host "Backend URL: $BackendUrl" -ForegroundColor Blue
Write-Host ""
Write-Host "⚠️  Note: You still need to set up the database manually" -ForegroundColor Yellow
Write-Host "1. Create a Cloud SQL PostgreSQL instance" -ForegroundColor Cyan
Write-Host "2. Update the backend environment variables with database connection details" -ForegroundColor Cyan
Write-Host "3. Run database migrations" -ForegroundColor Cyan
Write-Host ""
Write-Host "📚 For detailed instructions, see: docs/GCP_DEPLOYMENT_GUIDE.md" -ForegroundColor Blue
