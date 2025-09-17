#!/bin/bash

# Container Security Scanning Script
# This script performs security scanning on Docker images and containers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCAN_RESULTS_DIR="./security-reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create results directory
mkdir -p "$SCAN_RESULTS_DIR"

echo -e "${BLUE}🔍 Starting Container Security Scan - $TIMESTAMP${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to scan with Trivy
scan_with_trivy() {
    local image=$1
    local output_file="$SCAN_RESULTS_DIR/trivy_${image//\//_}_$TIMESTAMP.json"
    
    echo -e "${YELLOW}📊 Scanning $image with Trivy...${NC}"
    
    if command_exists trivy; then
        trivy image --format json --output "$output_file" "$image"
        echo -e "${GREEN}✅ Trivy scan completed: $output_file${NC}"
    else
        echo -e "${RED}❌ Trivy not installed. Installing via Docker...${NC}"
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
            -v "$PWD/$SCAN_RESULTS_DIR":/results \
            aquasec/trivy:latest image --format json --output "/results/trivy_${image//\//_}_$TIMESTAMP.json" "$image"
    fi
}

# Function to scan with Docker Scout (if available)
scan_with_scout() {
    local image=$1
    local output_file="$SCAN_RESULTS_DIR/scout_${image//\//_}_$TIMESTAMP.json"
    
    echo -e "${YELLOW}🔍 Scanning $image with Docker Scout...${NC}"
    
    if command_exists docker && docker scout version >/dev/null 2>&1; then
        docker scout cves --format json --output "$output_file" "$image" || true
        echo -e "${GREEN}✅ Docker Scout scan completed: $output_file${NC}"
    else
        echo -e "${YELLOW}⚠️  Docker Scout not available, skipping...${NC}"
    fi
}

# Function to perform container runtime security check
runtime_security_check() {
    echo -e "${YELLOW}🛡️  Performing runtime security checks...${NC}"
    
    local output_file="$SCAN_RESULTS_DIR/runtime_security_$TIMESTAMP.txt"
    
    {
        echo "=== Container Runtime Security Check ==="
        echo "Timestamp: $(date)"
        echo ""
        
        echo "=== Running Containers ==="
        docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        
        echo "=== Container Security Options ==="
        for container in $(docker ps --format "{{.Names}}"); do
            echo "Container: $container"
            docker inspect "$container" --format '{{.HostConfig.SecurityOpt}}' | grep -v "^\[\]$" || echo "  No security options set"
            echo "  Read-only: $(docker inspect "$container" --format '{{.HostConfig.ReadonlyRootfs}}')"
            echo "  Privileged: $(docker inspect "$container" --format '{{.HostConfig.Privileged}}')"
            echo "  User: $(docker inspect "$container" --format '{{.Config.User}}')"
            echo ""
        done
        
        echo "=== Network Security ==="
        docker network ls
        echo ""
        
        echo "=== Volume Mounts ==="
        for container in $(docker ps --format "{{.Names}}"); do
            echo "Container: $container"
            docker inspect "$container" --format '{{range .Mounts}}{{.Type}}: {{.Source}} -> {{.Destination}} ({{.Mode}}){{"\n"}}{{end}}'
            echo ""
        done
        
    } > "$output_file"
    
    echo -e "${GREEN}✅ Runtime security check completed: $output_file${NC}"
}

# Function to check Dockerfile security
dockerfile_security_check() {
    echo -e "${YELLOW}📋 Checking Dockerfile security...${NC}"
    
    local output_file="$SCAN_RESULTS_DIR/dockerfile_security_$TIMESTAMP.txt"
    
    {
        echo "=== Dockerfile Security Analysis ==="
        echo "Timestamp: $(date)"
        echo ""
        
        for dockerfile in $(find . -name "Dockerfile" -o -name "*.dockerfile"); do
            echo "=== Analyzing: $dockerfile ==="
            
            # Check for security best practices
            echo "Security checks for $dockerfile:"
            
            # Check for non-root user
            if grep -q "USER" "$dockerfile"; then
                echo "✅ Uses non-root user"
            else
                echo "❌ No USER directive found - running as root"
            fi
            
            # Check for COPY vs ADD
            if grep -q "ADD" "$dockerfile"; then
                echo "⚠️  Uses ADD command - consider COPY for better security"
            fi
            
            # Check for latest tag
            if grep -q ":latest" "$dockerfile"; then
                echo "⚠️  Uses :latest tag - consider pinning versions"
            fi
            
            # Check for secrets in build
            if grep -qE "(PASSWORD|SECRET|KEY|TOKEN)" "$dockerfile"; then
                echo "⚠️  Potential secrets in Dockerfile"
            fi
            
            # Check for security updates
            if grep -q "apk update\|apt-get update" "$dockerfile"; then
                echo "✅ Updates packages"
            else
                echo "⚠️  No package updates found"
            fi
            
            echo ""
        done
        
    } > "$output_file"
    
    echo -e "${GREEN}✅ Dockerfile security check completed: $output_file${NC}"
}

# Main scanning function
main() {
    echo -e "${BLUE}🚀 Container Security Scanning Suite${NC}"
    echo -e "${BLUE}====================================${NC}"
    
    # Build images if they don't exist
    echo -e "${YELLOW}🏗️  Building images...${NC}"
    docker-compose build --no-cache
    
    # Get list of images to scan
    local images=(
        "vulnerable-webapp-backend"
        "vulnerable-webapp-frontend"
        "postgres:14-alpine"
    )
    
    # Scan each image
    for image in "${images[@]}"; do
        echo -e "\n${BLUE}🔍 Scanning image: $image${NC}"
        scan_with_trivy "$image"
        scan_with_scout "$image"
    done
    
    # Perform runtime checks
    echo -e "\n${BLUE}🛡️  Runtime Security Analysis${NC}"
    runtime_security_check
    
    # Check Dockerfiles
    echo -e "\n${BLUE}📋 Dockerfile Security Analysis${NC}"
    dockerfile_security_check
    
    # Generate summary report
    generate_summary_report
    
    echo -e "\n${GREEN}✅ Security scanning completed!${NC}"
    echo -e "${GREEN}📊 Results saved in: $SCAN_RESULTS_DIR${NC}"
}

# Function to generate summary report
generate_summary_report() {
    local summary_file="$SCAN_RESULTS_DIR/security_summary_$TIMESTAMP.md"
    
    {
        echo "# Container Security Scan Summary"
        echo ""
        echo "**Scan Date:** $(date)"
        echo "**Scan ID:** $TIMESTAMP"
        echo ""
        
        echo "## Scanned Images"
        echo ""
        docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
        echo ""
        
        echo "## Security Findings"
        echo ""
        echo "### High Priority Issues"
        echo "- Review Trivy scan results for critical vulnerabilities"
        echo "- Ensure containers run as non-root users"
        echo "- Verify no secrets are embedded in images"
        echo ""
        
        echo "### Recommendations"
        echo "- Regularly update base images"
        echo "- Use multi-stage builds to reduce attack surface"
        echo "- Implement runtime security monitoring"
        echo "- Use read-only containers where possible"
        echo ""
        
        echo "## Files Generated"
        echo ""
        for file in "$SCAN_RESULTS_DIR"/*"$TIMESTAMP"*; do
            if [ -f "$file" ]; then
                echo "- $(basename "$file")"
            fi
        done
        
    } > "$summary_file"
    
    echo -e "${GREEN}📋 Summary report generated: $summary_file${NC}"
}

# Run main function
main "$@"