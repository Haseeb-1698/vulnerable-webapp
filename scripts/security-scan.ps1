# Container Security Scanning Script (PowerShell)
# This script performs security scanning on Docker images and containers

param(
    [string]$OutputDir = "./security-reports",
    [switch]$SkipBuild = $false
)

# Configuration
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ScanResultsDir = $OutputDir

# Create results directory
if (!(Test-Path $ScanResultsDir)) {
    New-Item -ItemType Directory -Path $ScanResultsDir -Force | Out-Null
}

Write-Host "🔍 Starting Container Security Scan - $Timestamp" -ForegroundColor Blue

# Function to check if command exists
function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Function to scan with Trivy
function Invoke-TrivyScan {
    param([string]$Image)
    
    $OutputFile = Join-Path $ScanResultsDir "trivy_$($Image -replace '[/:]', '_')_$Timestamp.json"
    
    Write-Host "📊 Scanning $Image with Trivy..." -ForegroundColor Yellow
    
    if (Test-Command "trivy") {
        trivy image --format json --output $OutputFile $Image
        Write-Host "✅ Trivy scan completed: $OutputFile" -ForegroundColor Green
    }
    else {
        Write-Host "❌ Trivy not installed. Using Docker..." -ForegroundColor Red
        $DockerOutputPath = "/results/trivy_$($Image -replace '[/:]', '_')_$Timestamp.json"
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "${PWD}/${ScanResultsDir}:/results" aquasec/trivy:latest image --format json --output $DockerOutputPath $Image
    }
}

# Function to scan with Docker Scout
function Invoke-ScoutScan {
    param([string]$Image)
    
    $OutputFile = Join-Path $ScanResultsDir "scout_$($Image -replace '[/:]', '_')_$Timestamp.json"
    
    Write-Host "🔍 Scanning $Image with Docker Scout..." -ForegroundColor Yellow
    
    try {
        docker scout version | Out-Null
        docker scout cves --format json --output $OutputFile $Image
        Write-Host "✅ Docker Scout scan completed: $OutputFile" -ForegroundColor Green
    }
    catch {
        Write-Host "⚠️  Docker Scout not available, skipping..." -ForegroundColor Yellow
    }
}

# Function to perform runtime security check
function Invoke-RuntimeSecurityCheck {
    Write-Host "🛡️  Performing runtime security checks..." -ForegroundColor Yellow
    
    $OutputFile = Join-Path $ScanResultsDir "runtime_security_$Timestamp.txt"
    
    $SecurityReport = @"
=== Container Runtime Security Check ===
Timestamp: $(Get-Date)

=== Running Containers ===
$(docker ps --format "table {{.Names}}`t{{.Image}}`t{{.Status}}`t{{.Ports}}")

=== Container Security Options ===
"@

    $Containers = docker ps --format "{{.Names}}"
    foreach ($Container in $Containers) {
        $SecurityOpt = docker inspect $Container --format '{{.HostConfig.SecurityOpt}}'
        $ReadOnly = docker inspect $Container --format '{{.HostConfig.ReadonlyRootfs}}'
        $Privileged = docker inspect $Container --format '{{.HostConfig.Privileged}}'
        $User = docker inspect $Container --format '{{.Config.User}}'
        
        $SecurityReport += @"

Container: $Container
  Security Options: $SecurityOpt
  Read-only: $ReadOnly
  Privileged: $Privileged
  User: $User
"@
    }

    $SecurityReport += @"

=== Network Security ===
$(docker network ls)

=== Volume Mounts ===
"@

    foreach ($Container in $Containers) {
        $Mounts = docker inspect $Container --format '{{range .Mounts}}{{.Type}}: {{.Source}} -> {{.Destination}} ({{.Mode}}){{"\n"}}{{end}}'
        $SecurityReport += @"

Container: $Container
$Mounts
"@
    }

    $SecurityReport | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "✅ Runtime security check completed: $OutputFile" -ForegroundColor Green
}

# Function to check Dockerfile security
function Invoke-DockerfileSecurityCheck {
    Write-Host "📋 Checking Dockerfile security..." -ForegroundColor Yellow
    
    $OutputFile = Join-Path $ScanResultsDir "dockerfile_security_$Timestamp.txt"
    
    $DockerfileReport = @"
=== Dockerfile Security Analysis ===
Timestamp: $(Get-Date)

"@

    $Dockerfiles = Get-ChildItem -Recurse -Name "Dockerfile*" -Include "Dockerfile", "*.dockerfile"
    
    foreach ($Dockerfile in $Dockerfiles) {
        $Content = Get-Content $Dockerfile -Raw
        
        $DockerfileReport += @"
=== Analyzing: $Dockerfile ===
Security checks for $Dockerfile:

"@

        # Check for non-root user
        if ($Content -match "USER") {
            $DockerfileReport += "✅ Uses non-root user`n"
        }
        else {
            $DockerfileReport += "❌ No USER directive found - running as root`n"
        }

        # Check for COPY vs ADD
        if ($Content -match "ADD") {
            $DockerfileReport += "⚠️  Uses ADD command - consider COPY for better security`n"
        }

        # Check for latest tag
        if ($Content -match ":latest") {
            $DockerfileReport += "⚠️  Uses :latest tag - consider pinning versions`n"
        }

        # Check for secrets
        if ($Content -match "(PASSWORD|SECRET|KEY|TOKEN)") {
            $DockerfileReport += "⚠️  Potential secrets in Dockerfile`n"
        }

        # Check for security updates
        if ($Content -match "(apk update|apt-get update)") {
            $DockerfileReport += "✅ Updates packages`n"
        }
        else {
            $DockerfileReport += "⚠️  No package updates found`n"
        }

        $DockerfileReport += "`n"
    }

    $DockerfileReport | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "✅ Dockerfile security check completed: $OutputFile" -ForegroundColor Green
}

# Function to generate summary report
function New-SummaryReport {
    $SummaryFile = Join-Path $ScanResultsDir "security_summary_$Timestamp.md"
    
    $Summary = @"
# Container Security Scan Summary

**Scan Date:** $(Get-Date)
**Scan ID:** $Timestamp

## Scanned Images

$(docker images --format "table {{.Repository}}`t{{.Tag}}`t{{.Size}}`t{{.CreatedAt}}")

## Security Findings

### High Priority Issues
- Review Trivy scan results for critical vulnerabilities
- Ensure containers run as non-root users
- Verify no secrets are embedded in images

### Recommendations
- Regularly update base images
- Use multi-stage builds to reduce attack surface
- Implement runtime security monitoring
- Use read-only containers where possible

## Files Generated

"@

    $GeneratedFiles = Get-ChildItem -Path $ScanResultsDir -Name "*$Timestamp*"
    foreach ($File in $GeneratedFiles) {
        $Summary += "- $File`n"
    }

    $Summary | Out-File -FilePath $SummaryFile -Encoding UTF8
    Write-Host "📋 Summary report generated: $SummaryFile" -ForegroundColor Green
}

# Main function
function Start-SecurityScan {
    Write-Host "🚀 Container Security Scanning Suite" -ForegroundColor Blue
    Write-Host "====================================" -ForegroundColor Blue
    
    # Build images if requested
    if (-not $SkipBuild) {
        Write-Host "🏗️  Building images..." -ForegroundColor Yellow
        docker-compose build --no-cache
    }
    
    # Images to scan
    $Images = @(
        "vulnerable-webapp-backend",
        "vulnerable-webapp-frontend",
        "postgres:14-alpine"
    )
    
    # Scan each image
    foreach ($Image in $Images) {
        Write-Host "`n🔍 Scanning image: $Image" -ForegroundColor Blue
        Invoke-TrivyScan -Image $Image
        Invoke-ScoutScan -Image $Image
    }
    
    # Perform runtime checks
    Write-Host "`n🛡️  Runtime Security Analysis" -ForegroundColor Blue
    Invoke-RuntimeSecurityCheck
    
    # Check Dockerfiles
    Write-Host "`n📋 Dockerfile Security Analysis" -ForegroundColor Blue
    Invoke-DockerfileSecurityCheck
    
    # Generate summary
    New-SummaryReport
    
    Write-Host "`n✅ Security scanning completed!" -ForegroundColor Green
    Write-Host "📊 Results saved in: $ScanResultsDir" -ForegroundColor Green
}

# Run the scan
Start-SecurityScan