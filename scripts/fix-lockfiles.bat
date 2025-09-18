@echo off
REM Fix package-lock.json files for Docker builds
REM This script regenerates lock files to ensure consistency

echo 🔧 Fixing package-lock.json files for Docker compatibility
echo ==========================================================

REM Check if we're in the project root
if not exist "package.json" (
    echo ✗ Please run this script from the project root directory
    exit /b 1
)

echo ✓ Project root detected

REM Fix backend lock file
echo.
echo 🔧 Fixing backend package-lock.json...
echo ------------------------------------

if exist "backend" (
    cd backend
    
    REM Remove existing lock file and node_modules
    if exist "package-lock.json" (
        del package-lock.json
        echo ✓ Removed old backend package-lock.json
    )
    
    if exist "node_modules" (
        rmdir /s /q node_modules
        echo ✓ Removed backend node_modules
    )
    
    REM Regenerate lock file
    npm install
    if %errorlevel% equ 0 (
        echo ✓ Generated new backend package-lock.json
    ) else (
        echo ✗ Failed to generate backend package-lock.json
        exit /b 1
    )
    
    cd ..
) else (
    echo ⚠ Backend directory not found
)

REM Fix frontend lock file
echo.
echo 🎨 Fixing frontend package-lock.json...
echo -------------------------------------

if exist "frontend" (
    cd frontend
    
    REM Remove existing lock file and node_modules
    if exist "package-lock.json" (
        del package-lock.json
        echo ✓ Removed old frontend package-lock.json
    )
    
    if exist "node_modules" (
        rmdir /s /q node_modules
        echo ✓ Removed frontend node_modules
    )
    
    REM Regenerate lock file
    npm install
    if %errorlevel% equ 0 (
        echo ✓ Generated new frontend package-lock.json
    ) else (
        echo ✗ Failed to generate frontend package-lock.json
        exit /b 1
    )
    
    cd ..
) else (
    echo ⚠ Frontend directory not found
)

REM Fix root lock file if it exists
echo.
echo 📦 Fixing root package-lock.json...
echo ---------------------------------

if exist "package-lock.json" (
    del package-lock.json
    echo ✓ Removed old root package-lock.json
)

if exist "node_modules" (
    rmdir /s /q node_modules
    echo ✓ Removed root node_modules
)

npm install
if %errorlevel% equ 0 (
    echo ✓ Generated new root package-lock.json
) else (
    echo ✗ Failed to generate root package-lock.json
    exit /b 1
)

echo.
echo 🎉 Lock files fixed successfully!
echo ===============================
echo.
echo Next steps:
echo 1. Commit the updated lock files:
echo    git add .
echo    git commit -m "Fix package-lock.json files for Docker builds"
echo    git push origin main
echo.
echo 2. The Docker builds should now work correctly
echo.

pause