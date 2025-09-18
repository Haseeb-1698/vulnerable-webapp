@echo off
REM Docker Build Test Script for Windows
REM Tests local Docker builds to ensure they work before pushing to GitHub

echo 🐳 Testing Docker Build Setup
echo ==============================

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo ✗ Docker is not running. Please start Docker and try again.
    exit /b 1
)

echo ✓ Docker is running

REM Test backend build
echo.
echo 🔧 Testing Backend Docker Build...
echo --------------------------------

docker build -t vulnerable-webapp-backend:test ./backend --target production
if %errorlevel% neq 0 (
    echo ✗ Backend Docker build failed
    exit /b 1
)

echo ✓ Backend Docker build successful

REM Clean up backend test image
docker rmi vulnerable-webapp-backend:test >nul 2>&1
echo ✓ Backend test image cleaned up

REM Test frontend build
echo.
echo 🎨 Testing Frontend Docker Build...
echo ---------------------------------

docker build -t vulnerable-webapp-frontend:test ./frontend --target production
if %errorlevel% neq 0 (
    echo ✗ Frontend Docker build failed
    exit /b 1
)

echo ✓ Frontend Docker build successful

REM Clean up frontend test image
docker rmi vulnerable-webapp-frontend:test >nul 2>&1
echo ✓ Frontend test image cleaned up

REM Test Docker Compose
echo.
echo 🐙 Testing Docker Compose...
echo ---------------------------

docker-compose config >nul 2>&1
if %errorlevel% neq 0 (
    echo ✗ Docker Compose configuration has errors
    exit /b 1
)

echo ✓ Docker Compose configuration is valid

echo.
echo 🎉 All Docker tests passed!
echo ==========================
echo.
echo Your Docker setup is ready for GitHub Actions!
echo.
echo Next steps:
echo 1. Set up Docker Hub secrets in GitHub (see README.md)
echo 2. Push your changes to trigger the GitHub Actions workflow
echo 3. Monitor the workflow in the Actions tab of your GitHub repository
echo.

pause