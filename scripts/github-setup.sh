#!/bin/bash

# GitHub Repository Setup Script
# This script helps set up your project for GitHub deployment

set -e

echo "🚀 Setting up GitHub repository for Vulnerable Web Application"
echo "=============================================================="

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed. Please install Git first."
    exit 1
fi

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "📁 Initializing Git repository..."
    git init
    echo "✅ Git repository initialized"
fi

# Create .gitignore if it doesn't exist
if [ ! -f ".gitignore" ]; then
    echo "📝 Creating .gitignore file..."
    cat > .gitignore << 'EOF'
# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.development.local
.env.test.local
.env.production.local
.env.production

# Build outputs
dist/
build/
*.tsbuildinfo

# Logs
logs/
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Runtime data
pids/
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
*.lcov

# nyc test coverage
.nyc_output

# Dependency directories
node_modules/
jspm_packages/

# Optional npm cache directory
.npm

# Optional eslint cache
.eslintcache

# Microbundle cache
.rpt2_cache/
.rts2_cache_cjs/
.rts2_cache_es/
.rts2_cache_umd/

# Optional REPL history
.node_repl_history

# Output of 'npm pack'
*.tgz

# Yarn Integrity file
.yarn-integrity

# parcel-bundler cache (https://parceljs.org/)
.cache
.parcel-cache

# Next.js build output
.next

# Nuxt.js build / generate output
.nuxt
dist

# Gatsby files
.cache/
public

# Storybook build outputs
.out
.storybook-out

# Temporary folders
tmp/
temp/

# Editor directories and files
.vscode/
.idea/
*.swp
*.swo
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# Docker
.dockerignore

# Database
*.db
*.sqlite

# Uploads (keep structure but ignore files)
uploads/*
!uploads/.gitkeep

# Security reports
security-reports/
*.report

# SSL certificates
*.pem
*.key
*.crt

# Backup files
*.backup
*.bak
EOF
    echo "✅ .gitignore file created"
fi

# Create README.md if it doesn't exist
if [ ! -f "README.md" ]; then
    echo "📝 Creating basic README.md..."
    cat > README.md << 'EOF'
# Vulnerable Web Application

A comprehensive security testing lab application built with modern web technologies.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/vulnerable-webapp.git
cd vulnerable-webapp

# Start the application
.\scripts\deploy.ps1 -Environment development -EnableMonitoring
```

## Features

- Modern React frontend with TypeScript
- Node.js backend with Express
- PostgreSQL database
- Comprehensive security testing scenarios
- Real-time monitoring and logging
- Docker containerization

## Documentation

See the `docs/` directory for detailed documentation.

## Security Notice

⚠️ **This application contains intentional security vulnerabilities for educational purposes. Do not deploy to production environments.**
EOF
    echo "✅ Basic README.md created"
fi

# Add all files to git
echo "📦 Adding files to Git..."
git add .

# Check if there are changes to commit
if git diff --staged --quiet; then
    echo "ℹ️  No changes to commit"
else
    echo "💾 Committing changes..."
    git commit -m "Initial commit: Vulnerable Web Application

- Complete containerized application
- Security testing lab environment
- Monitoring and logging capabilities
- Production-ready deployment scripts"
    echo "✅ Changes committed"
fi

echo ""
echo "🎉 Repository setup complete!"
echo ""
echo "Next steps:"
echo "1. Create a new repository on GitHub"
echo "2. Add the remote origin:"
echo "   git remote add origin https://github.com/yourusername/vulnerable-webapp.git"
echo "3. Push to GitHub:"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "For Docker Hub deployment:"
echo "1. Set up GitHub Secrets: DOCKER_USERNAME and DOCKER_PASSWORD"
echo "2. The GitHub Actions workflow will automatically build and push images"
echo ""
echo "Happy coding! 🚀"
