# Deployment Script for Vulnerable Web Application
# Handles environment setup and container deployment

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("development", "production", "hardened")]
    [string]$Environment = "development",
    
    [switch]$SkipBuild = $false,
    [switch]$RunSecurityScan = $false,
    [switch]$CleanStart = $false,
    [switch]$EnableMonitoring = $false
)

# Configuration
$ProjectName = "vulnerable-webapp"
$ComposeFiles = @{
    "development" = "docker-compose.yml"
    "production" = "docker-compose.prod.yml"
    "hardened" = "docker-hardening.yml"
}

Write-Host "🚀 Deploying Vulnerable Web Application" -ForegroundColor Blue
Write-Host "Environment: $Environment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Blue

# Function to check prerequisites
function Test-Prerequisites {
    Write-Host "🔍 Checking prerequisites..." -ForegroundColor Yellow
    
    $Prerequisites = @("docker", "docker-compose")
    $Missing = @()
    
    foreach ($Tool in $Prerequisites) {
        try {
            & $Tool --version | Out-Null
            Write-Host "✅ $Tool is installed" -ForegroundColor Green
        }
        catch {
            Write-Host "❌ $Tool is not installed" -ForegroundColor Red
            $Missing += $Tool
        }
    }
    
    if ($Missing.Count -gt 0) {
        Write-Host "❌ Missing prerequisites: $($Missing -join ', ')" -ForegroundColor Red
        Write-Host "Please install the missing tools and try again." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✅ All prerequisites satisfied" -ForegroundColor Green
}

# Function to setup environment variables
function Initialize-Environment {
    param([string]$Env)
    
    Write-Host "🔧 Setting up environment variables..." -ForegroundColor Yellow
    
    $EnvFile = switch ($Env) {
        "production" { ".env.production" }
        "hardened" { ".env.production" }
        default { ".env" }
    }
    
    # Check if environment file exists
    if (!(Test-Path $EnvFile)) {
        $ExampleFile = "$EnvFile.example"
        if (Test-Path $ExampleFile) {
            Write-Host "📋 Creating $EnvFile from $ExampleFile" -ForegroundColor Cyan
            Copy-Item $ExampleFile $EnvFile
            Write-Host "⚠️  Please review and update $EnvFile with your configuration" -ForegroundColor Yellow
        }
        else {
            Write-Host "❌ Environment file $EnvFile not found and no example available" -ForegroundColor Red
            exit 1
        }
    }
    
    # Load environment variables
    if (Test-Path $EnvFile) {
        Write-Host "📂 Loading environment from $EnvFile" -ForegroundColor Cyan
        Get-Content $EnvFile | ForEach-Object {
            if ($_ -match '^([^#][^=]+)=(.*)$') {
                [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
            }
        }
    }
    
    Write-Host "✅ Environment configured" -ForegroundColor Green
}

# Function to create required directories
function New-RequiredDirectories {
    Write-Host "📁 Creating required directories..." -ForegroundColor Yellow
    
    $Directories = @(
        "data/postgres",
        "data/uploads", 
        "data/logs",
        "security-reports",
        "nginx/ssl"
    )
    
    foreach ($Dir in $Directories) {
        if (!(Test-Path $Dir)) {
            New-Item -ItemType Directory -Path $Dir -Force | Out-Null
            Write-Host "📁 Created directory: $Dir" -ForegroundColor Cyan
        }
    }
    
    Write-Host "✅ Directories created" -ForegroundColor Green
}

# Function to clean existing containers
function Remove-ExistingContainers {
    Write-Host "🧹 Cleaning existing containers..." -ForegroundColor Yellow
    
    try {
        docker-compose -p $ProjectName down --volumes --remove-orphans
        Write-Host "✅ Existing containers cleaned" -ForegroundColor Green
    }
    catch {
        Write-Host "⚠️  No existing containers to clean" -ForegroundColor Yellow
    }
}

# Function to build and start services
function Start-Services {
    param([string]$ComposeFile, [bool]$Build, [bool]$EnableMonitoring = $false)
    
    Write-Host "🏗️  Starting services with $ComposeFile..." -ForegroundColor Yellow
    
    $ComposeArgs = @("-f", $ComposeFile, "-p", $ProjectName)
    
    # Add monitoring compose file if enabled
    if ($EnableMonitoring) {
        $ComposeArgs += @("-f", "docker-compose.monitoring.yml")
        Write-Host "📊 Monitoring services enabled" -ForegroundColor Cyan
    }
    
    if ($Build) {
        Write-Host "🔨 Building images..." -ForegroundColor Cyan
        & docker-compose @ComposeArgs build --no-cache
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Build failed" -ForegroundColor Red
            exit 1
        }
    }
    
    Write-Host "🚀 Starting containers..." -ForegroundColor Cyan
    if ($EnableMonitoring) {
        # Start with monitoring profile
        & docker-compose @ComposeArgs --profile monitoring up -d
    } else {
        & docker-compose @ComposeArgs up -d
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to start containers" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✅ Services started successfully" -ForegroundColor Green
}

# Function to wait for services to be healthy
function Wait-ForServices {
    Write-Host "⏳ Waiting for services to be healthy..." -ForegroundColor Yellow
    
    $MaxAttempts = 30
    $Attempt = 0
    
    do {
        $Attempt++
        Start-Sleep -Seconds 2
        
        $HealthyServices = docker-compose -p $ProjectName ps --services --filter "status=running" | Measure-Object | Select-Object -ExpandProperty Count
        $TotalServices = docker-compose -p $ProjectName ps --services | Measure-Object | Select-Object -ExpandProperty Count
        
        Write-Host "Attempt $Attempt/$MaxAttempts - Healthy services: $HealthyServices/$TotalServices" -ForegroundColor Cyan
        
        if ($HealthyServices -eq $TotalServices -and $TotalServices -gt 0) {
            Write-Host "✅ All services are healthy" -ForegroundColor Green
            return $true
        }
    } while ($Attempt -lt $MaxAttempts)
    
    Write-Host "⚠️  Services may not be fully healthy yet" -ForegroundColor Yellow
    return $false
}

# Function to display service information
function Show-ServiceInfo {
    Write-Host "📊 Service Information:" -ForegroundColor Blue
    Write-Host "======================" -ForegroundColor Blue
    
    # Show running containers
    docker-compose -p $ProjectName ps
    
    Write-Host "`n🌐 Application URLs:" -ForegroundColor Blue
    
    $FrontendPort = [Environment]::GetEnvironmentVariable("FRONTEND_PORT") ?? "3000"
    $BackendPort = [Environment]::GetEnvironmentVariable("BACKEND_PORT") ?? "3001"
    
    Write-Host "Frontend: http://localhost:$FrontendPort" -ForegroundColor Cyan
    Write-Host "Backend API: http://localhost:$BackendPort/api" -ForegroundColor Cyan
    Write-Host "Health Check: http://localhost:$BackendPort/health" -ForegroundColor Cyan
    
    if ($Environment -eq "production") {
        Write-Host "Production Frontend: http://localhost:80" -ForegroundColor Cyan
    }
}

# Function to run security scan
function Invoke-SecurityScan {
    if (Test-Path "scripts/security-scan.ps1") {
        Write-Host "🔍 Running security scan..." -ForegroundColor Yellow
        & "scripts/security-scan.ps1" -SkipBuild
    }
    else {
        Write-Host "⚠️  Security scan script not found" -ForegroundColor Yellow
    }
}

# Main deployment function
function Start-Deployment {
    Write-Host "🎯 Starting deployment process..." -ForegroundColor Blue
    
    # Check prerequisites
    Test-Prerequisites
    
    # Setup environment
    Initialize-Environment -Env $Environment
    
    # Create directories
    New-RequiredDirectories
    
    # Clean start if requested
    if ($CleanStart) {
        Remove-ExistingContainers
    }
    
    # Get compose file
    $ComposeFile = $ComposeFiles[$Environment]
    if (!(Test-Path $ComposeFile)) {
        Write-Host "❌ Compose file not found: $ComposeFile" -ForegroundColor Red
        exit 1
    }
    
    # Start services
    Start-Services -ComposeFile $ComposeFile -Build (-not $SkipBuild) -EnableMonitoring $EnableMonitoring
    
    # Wait for services
    Wait-ForServices
    
    # Show service info
    Show-ServiceInfo
    
    # Run security scan if requested
    if ($RunSecurityScan) {
        Invoke-SecurityScan
    }
    
    Write-Host "`n🎉 Deployment completed successfully!" -ForegroundColor Green
    Write-Host "Environment: $Environment" -ForegroundColor Cyan
    
    if ($Environment -eq "development") {
        Write-Host "`n💡 Development Tips:" -ForegroundColor Yellow
        Write-Host "- Use 'docker-compose logs -f' to view logs" -ForegroundColor Cyan
        Write-Host "- Use 'docker-compose exec backend npm run db:migrate' to run migrations" -ForegroundColor Cyan
        Write-Host "- Use 'docker-compose exec backend npm run db:seed' to seed the database" -ForegroundColor Cyan
    }
}

# Run deployment
try {
    Start-Deployment
}
catch {
    Write-Host "❌ Deployment failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}