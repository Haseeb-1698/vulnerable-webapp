@echo off
echo 🚀 Setting up Vulnerable Web Application...

REM Check if Docker is installed
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker is not installed. Please install Docker first.
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js 18+ first.
    exit /b 1
)

echo ✅ Prerequisites check passed

REM Install root dependencies
echo 📦 Installing root dependencies...
npm install

REM Install frontend dependencies
echo 📦 Installing frontend dependencies...
cd frontend
npm install
cd ..

REM Install backend dependencies
echo 📦 Installing backend dependencies...
cd backend
npm install
cd ..

REM Copy environment file
echo ⚙️ Setting up environment variables...
if not exist backend\.env (
    copy backend\.env.example backend\.env
    echo ✅ Created backend/.env file
) else (
    echo ⚠️ backend/.env already exists, skipping...
)

REM Start PostgreSQL database
echo 🐘 Starting PostgreSQL database...
docker-compose up -d postgres

REM Wait for database to be ready
echo ⏳ Waiting for database to be ready...
timeout /t 10 /nobreak >nul

REM Generate Prisma client
echo 🔧 Generating Prisma client...
cd backend
npm run db:generate

REM Run database migrations
echo 🗄️ Running database migrations...
npm run db:migrate

REM Seed the database
echo 🌱 Seeding database with demo data...
npm run db:seed

cd ..

echo.
echo 🎉 Setup completed successfully!
echo.
echo 📋 Next steps:
echo   1. Start the development servers: npm run dev
echo   2. Open your browser to http://localhost:3000
echo   3. Use demo credentials:
echo      - alice@example.com / password123
echo      - bob@example.com / password123
echo      - charlie@example.com / password123
echo.
echo ⚠️  WARNING: This application contains intentional security vulnerabilities
echo    Use only in isolated development environments!
echo.