#!/bin/bash

# Fix package-lock.json files for Docker builds
# This script regenerates lock files to ensure consistency

echo "🔧 Fixing package-lock.json files for Docker compatibility"
echo "=========================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if we're in the project root
if [ ! -f "package.json" ]; then
    print_error "Please run this script from the project root directory"
    exit 1
fi

print_status "Project root detected"

# Fix backend lock file
echo ""
echo "🔧 Fixing backend package-lock.json..."
echo "------------------------------------"

if [ -d "backend" ]; then
    cd backend
    
    # Remove existing lock file and node_modules
    if [ -f "package-lock.json" ]; then
        rm package-lock.json
        print_status "Removed old backend package-lock.json"
    fi
    
    if [ -d "node_modules" ]; then
        rm -rf node_modules
        print_status "Removed backend node_modules"
    fi
    
    # Regenerate lock file
    npm install
    if [ $? -eq 0 ]; then
        print_status "Generated new backend package-lock.json"
    else
        print_error "Failed to generate backend package-lock.json"
        exit 1
    fi
    
    cd ..
else
    print_warning "Backend directory not found"
fi

# Fix frontend lock file
echo ""
echo "🎨 Fixing frontend package-lock.json..."
echo "-------------------------------------"

if [ -d "frontend" ]; then
    cd frontend
    
    # Remove existing lock file and node_modules
    if [ -f "package-lock.json" ]; then
        rm package-lock.json
        print_status "Removed old frontend package-lock.json"
    fi
    
    if [ -d "node_modules" ]; then
        rm -rf node_modules
        print_status "Removed frontend node_modules"
    fi
    
    # Regenerate lock file
    npm install
    if [ $? -eq 0 ]; then
        print_status "Generated new frontend package-lock.json"
    else
        print_error "Failed to generate frontend package-lock.json"
        exit 1
    fi
    
    cd ..
else
    print_warning "Frontend directory not found"
fi

# Fix root lock file if it exists
echo ""
echo "📦 Fixing root package-lock.json..."
echo "---------------------------------"

if [ -f "package-lock.json" ]; then
    rm package-lock.json
    print_status "Removed old root package-lock.json"
fi

if [ -d "node_modules" ]; then
    rm -rf node_modules
    print_status "Removed root node_modules"
fi

npm install
if [ $? -eq 0 ]; then
    print_status "Generated new root package-lock.json"
else
    print_error "Failed to generate root package-lock.json"
    exit 1
fi

echo ""
echo "🎉 Lock files fixed successfully!"
echo "==============================="
echo ""
echo "Next steps:"
echo "1. Commit the updated lock files:"
echo "   git add ."
echo "   git commit -m \"Fix package-lock.json files for Docker builds\""
echo "   git push origin main"
echo ""
echo "2. The Docker builds should now work correctly"
echo ""