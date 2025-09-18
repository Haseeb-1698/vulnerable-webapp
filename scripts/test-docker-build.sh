#!/bin/bash

# Docker Build Test Script
# Tests local Docker builds to ensure they work before pushing to GitHub

set -e

echo "🐳 Testing Docker Build Setup"
echo "=============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

print_status "Docker is running"

# Test backend build
echo ""
echo "🔧 Testing Backend Docker Build..."
echo "--------------------------------"

if docker build -t vulnerable-webapp-backend:test ./backend --target production; then
    print_status "Backend Docker build successful"
    
    # Test if the image was created
    if docker images | grep -q "vulnerable-webapp-backend.*test"; then
        print_status "Backend image created successfully"
        
        # Clean up test image
        docker rmi vulnerable-webapp-backend:test > /dev/null 2>&1
        print_status "Backend test image cleaned up"
    else
        print_error "Backend image not found after build"
        exit 1
    fi
else
    print_error "Backend Docker build failed"
    exit 1
fi

# Test frontend build
echo ""
echo "🎨 Testing Frontend Docker Build..."
echo "---------------------------------"

if docker build -t vulnerable-webapp-frontend:test ./frontend --target production; then
    print_status "Frontend Docker build successful"
    
    # Test if the image was created
    if docker images | grep -q "vulnerable-webapp-frontend.*test"; then
        print_status "Frontend image created successfully"
        
        # Clean up test image
        docker rmi vulnerable-webapp-frontend:test > /dev/null 2>&1
        print_status "Frontend test image cleaned up"
    else
        print_error "Frontend image not found after build"
        exit 1
    fi
else
    print_error "Frontend Docker build failed"
    exit 1
fi

# Test multi-stage builds
echo ""
echo "🏗️ Testing Multi-Stage Builds..."
echo "-------------------------------"

# Test backend development stage
if docker build -t vulnerable-webapp-backend:dev ./backend --target development; then
    print_status "Backend development stage build successful"
    docker rmi vulnerable-webapp-backend:dev > /dev/null 2>&1
else
    print_error "Backend development stage build failed"
    exit 1
fi

# Test frontend development stage
if docker build -t vulnerable-webapp-frontend:dev ./frontend --target development; then
    print_status "Frontend development stage build successful"
    docker rmi vulnerable-webapp-frontend:dev > /dev/null 2>&1
else
    print_error "Frontend development stage build failed"
    exit 1
fi

# Test Docker Compose
echo ""
echo "🐙 Testing Docker Compose..."
echo "---------------------------"

if docker-compose config > /dev/null 2>&1; then
    print_status "Docker Compose configuration is valid"
else
    print_error "Docker Compose configuration has errors"
    exit 1
fi

# Test production Docker Compose
if [ -f "docker-compose.prod.yml" ]; then
    if docker-compose -f docker-compose.prod.yml config > /dev/null 2>&1; then
        print_status "Production Docker Compose configuration is valid"
    else
        print_warning "Production Docker Compose configuration has errors"
    fi
fi

# Check for security best practices
echo ""
echo "🔒 Security Check..."
echo "------------------"

# Check if Dockerfiles use non-root users
if grep -q "USER nodejs" ./backend/Dockerfile && grep -q "user nginx" ./frontend/nginx.conf; then
    print_status "Non-root users configured correctly"
else
    print_warning "Check non-root user configuration in Dockerfiles"
fi

# Check for health checks
if grep -q "HEALTHCHECK" ./backend/Dockerfile && grep -q "HEALTHCHECK" ./frontend/Dockerfile; then
    print_status "Health checks configured"
else
    print_warning "Consider adding health checks to Dockerfiles"
fi

# Check for security updates
if grep -q "apk update && apk upgrade" ./backend/Dockerfile && grep -q "apk update && apk upgrade" ./frontend/Dockerfile; then
    print_status "Security updates included in builds"
else
    print_warning "Consider including security updates in Dockerfiles"
fi

echo ""
echo "🎉 All Docker tests passed!"
echo "=========================="
echo ""
echo "Your Docker setup is ready for GitHub Actions!"
echo ""
echo "Next steps:"
echo "1. Set up Docker Hub secrets in GitHub (see instructions below)"
echo "2. Push your changes to trigger the GitHub Actions workflow"
echo "3. Monitor the workflow in the Actions tab of your GitHub repository"
echo ""