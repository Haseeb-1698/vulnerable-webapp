# Docker Setup Guide

This guide will help you set up Docker builds and GitHub Actions integration for the Vulnerable Web Application project.

## 🐳 Local Docker Testing

Before setting up GitHub Actions, test your Docker builds locally to ensure everything works correctly.

### Prerequisites

- Docker Desktop installed and running
- Git repository cloned locally

### Testing Commands

**Unix/Linux/macOS:**
```bash
# Make the script executable
chmod +x scripts/test-docker-build.sh

# Run the test script
./scripts/test-docker-build.sh
```

**Windows:**
```cmd
# Run the test script
scripts\test-docker-build.bat
```

### Manual Testing

If you prefer to test manually:

```bash
# Test backend build
docker build -t vulnerable-webapp-backend:test ./backend --target production

# Test frontend build  
docker build -t vulnerable-webapp-frontend:test ./frontend --target production

# Test Docker Compose
docker-compose config

# Clean up test images
docker rmi vulnerable-webapp-backend:test vulnerable-webapp-frontend:test
```

## 🚀 GitHub Actions Setup

The GitHub Actions workflow will automatically build and push Docker images when you push code to the repository.

### Step 1: Create Docker Hub Account

1. Go to [Docker Hub](https://hub.docker.com/)
2. Create an account or sign in
3. Create a new repository for your project:
   - Repository name: `vulnerable-webapp` (or your preferred name)
   - Visibility: Public (for free accounts)

### Step 2: Generate Docker Hub Access Token

1. Go to Docker Hub → Account Settings → Security
2. Click "New Access Token"
3. Name: `GitHub Actions`
4. Permissions: `Read, Write, Delete`
5. Copy the generated token (you won't see it again!)

### Step 3: Configure GitHub Secrets

1. Go to your GitHub repository
2. Navigate to Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Add these secrets:

**DOCKER_USERNAME**
- Name: `DOCKER_USERNAME`
- Secret: Your Docker Hub username

**DOCKER_PASSWORD**
- Name: `DOCKER_PASSWORD`  
- Secret: The access token you generated in Step 2

### Step 4: Update Repository Name (Optional)

If your Docker Hub repository name differs from your GitHub repository name, update the workflow:

1. Edit `.github/workflows/docker-build.yml`
2. Change the `IMAGE_NAME` environment variable:
   ```yaml
   env:
     REGISTRY: docker.io
     IMAGE_NAME: your-dockerhub-username/your-repo-name
   ```

## 🔧 Workflow Behavior

### When Builds Trigger

- **Push to main/develop**: Builds and pushes images with tags
- **Pull requests**: Builds images but doesn't push (for testing)
- **Manual trigger**: Can be triggered manually from Actions tab

### Image Tags

The workflow creates multiple tags for each image:

- `latest` (for main branch)
- `main` or `develop` (branch name)
- `main-abc1234` (branch + commit SHA)
- `pr-123` (for pull requests)

### Example Generated Images

For repository `haseeb-1698/vulnerable-webapp`:

**Backend:**
- `haseeb-1698/vulnerable-webapp-backend:latest`
- `haseeb-1698/vulnerable-webapp-backend:main`
- `haseeb-1698/vulnerable-webapp-backend:main-abc1234`

**Frontend:**
- `haseeb-1698/vulnerable-webapp-frontend:latest`
- `haseeb-1698/vulnerable-webapp-frontend:main`
- `haseeb-1698/vulnerable-webapp-frontend:main-abc1234`

## 🐙 Docker Compose Usage

### Development

```bash
# Start all services for development
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production

```bash
# Start production services
docker-compose -f docker-compose.prod.yml up -d

# With custom images
IMAGE_TAG=latest docker-compose -f docker-compose.prod.yml up -d
```

## 🔒 Security Features

### Multi-Stage Builds

- **Development stage**: Includes dev dependencies and tools
- **Builder stage**: Compiles and builds the application
- **Production stage**: Minimal runtime image with only necessary files

### Security Hardening

- Non-root users (nodejs, nginx)
- Security updates installed
- Minimal attack surface
- Health checks included
- Proper file permissions

### Environment Variables

Create `.env` files for different environments:

```bash
# .env.development
NODE_ENV=development
DATABASE_URL=postgresql://webapp_user:webapp_password@localhost:5432/vulnerable_webapp
JWT_SECRET=dev-secret-key

# .env.production  
NODE_ENV=production
DATABASE_URL=postgresql://webapp_user:secure_password@db:5432/vulnerable_webapp
JWT_SECRET=production-secret-key
```

## 🚨 Troubleshooting

### Common Issues

**1. Docker build fails with permission errors**
```bash
# Fix file permissions
chmod +x scripts/*.sh
```

**2. GitHub Actions fails with "Username and password required"**
- Check that `DOCKER_USERNAME` and `DOCKER_PASSWORD` secrets are set
- Verify the access token has correct permissions

**3. Image push fails with "repository does not exist"**
- Create the repository on Docker Hub first
- Check the `IMAGE_NAME` in the workflow file

**4. Frontend build fails**
- Ensure `nginx.conf` exists in the frontend directory
- Check that all dependencies are properly installed

### Debug Commands

```bash
# Check Docker daemon
docker info

# List images
docker images

# Check running containers
docker ps

# View container logs
docker logs <container-name>

# Inspect image
docker inspect <image-name>
```

### Workflow Debugging

1. Go to GitHub repository → Actions tab
2. Click on the failed workflow run
3. Expand the failed step to see detailed logs
4. Check for specific error messages

## 📊 Monitoring

### Health Checks

Both images include health checks:

**Backend:**
```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"
```

**Frontend:**
```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1
```

### Monitoring Commands

```bash
# Check health status
docker ps --format "table {{.Names}}\t{{.Status}}"

# Monitor resource usage
docker stats

# Check logs
docker-compose logs -f --tail=100
```

## 🎯 Next Steps

1. **Test locally** using the provided scripts
2. **Set up GitHub secrets** for Docker Hub integration
3. **Push changes** to trigger the workflow
4. **Monitor the build** in GitHub Actions
5. **Deploy using** the generated Docker images

## 📚 Additional Resources

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Docker Hub Documentation](https://docs.docker.com/docker-hub/)
- [Multi-stage Builds](https://docs.docker.com/develop/dev-best-practices/dockerfile_best-practices/#use-multi-stage-builds)