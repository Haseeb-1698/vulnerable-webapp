#!/bin/bash

# Vulnerable Web Application Setup Script
echo "🚀 Setting up Vulnerable Web Application..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

echo "✅ Prerequisites check passed"

# Install root dependencies
echo "📦 Installing root dependencies..."
npm install

# Install frontend dependencies
echo "📦 Installing frontend dependencies..."
cd frontend
npm install
cd ..

# Install backend dependencies
echo "📦 Installing backend dependencies..."
cd backend
npm install
cd ..

# Copy environment file
echo "⚙️ Setting up environment variables..."
if [ ! -f backend/.env ]; then
    cp backend/.env.example backend/.env
    echo "✅ Created backend/.env file"
else
    echo "⚠️ backend/.env already exists, skipping..."
fi

# Start PostgreSQL database
echo "🐘 Starting PostgreSQL database..."
docker-compose up -d postgres

# Wait for database to be ready
echo "⏳ Waiting for database to be ready..."
sleep 10

# Generate Prisma client
echo "🔧 Generating Prisma client..."
cd backend
npm run db:generate

# Run database migrations
echo "🗄️ Running database migrations..."
npm run db:migrate

# Seed the database
echo "🌱 Seeding database with demo data..."
npm run db:seed

cd ..

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "📋 Next steps:"
echo "  1. Start the development servers: npm run dev"
echo "  2. Open your browser to http://localhost:3000"
echo "  3. Use demo credentials:"
echo "     - alice@example.com / password123"
echo "     - bob@example.com / password123"
echo "     - charlie@example.com / password123"
echo ""
echo "⚠️  WARNING: This application contains intentional security vulnerabilities"
echo "   Use only in isolated development environments!"
echo ""