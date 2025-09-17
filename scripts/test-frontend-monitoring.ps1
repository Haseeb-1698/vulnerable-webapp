# Test Frontend Monitoring Pages
Write-Host "Testing Frontend Monitoring Pages" -ForegroundColor Cyan

try {
    # Test if frontend is running
    Write-Host "Testing frontend server..." -ForegroundColor Yellow
    try {
        $frontendResponse = Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing -TimeoutSec 5
        Write-Host "Frontend server: OK" -ForegroundColor Green
    } catch {
        Write-Host "Frontend server: NOT RUNNING - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please start the frontend server with: npm start" -ForegroundColor Yellow
        return
    }
    
    # Test monitoring page directly
    Write-Host "`nTesting monitoring page..." -ForegroundColor Yellow
    try {
        $monitoringResponse = Invoke-WebRequest -Uri "http://localhost:3000/monitoring" -UseBasicParsing -TimeoutSec 10
        if ($monitoringResponse.StatusCode -eq 200) {
            Write-Host "Monitoring page: ACCESSIBLE" -ForegroundColor Green
            
            # Check if it contains expected content
            $content = $monitoringResponse.Content
            if ($content -match "monitoring|dashboard|performance") {
                Write-Host "  Content: Contains monitoring-related content" -ForegroundColor Green
            } else {
                Write-Host "  Content: May be showing login or error page" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "Monitoring page: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Test logs page directly
    Write-Host "`nTesting logs page..." -ForegroundColor Yellow
    try {
        $logsResponse = Invoke-WebRequest -Uri "http://localhost:3000/logs" -UseBasicParsing -TimeoutSec 10
        if ($logsResponse.StatusCode -eq 200) {
            Write-Host "Logs page: ACCESSIBLE" -ForegroundColor Green
            
            # Check if it contains expected content
            $content = $logsResponse.Content
            if ($content -match "logs|audit|entries") {
                Write-Host "  Content: Contains logs-related content" -ForegroundColor Green
            } else {
                Write-Host "  Content: May be showing login or error page" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "Logs page: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`nFrontend monitoring test completed!" -ForegroundColor Cyan
    Write-Host "`nTo test manually:" -ForegroundColor White
    Write-Host "1. Make sure both backend and frontend are running" -ForegroundColor Gray
    Write-Host "2. Go to http://localhost:3000" -ForegroundColor Gray
    Write-Host "3. Login with alice@example.com / password123" -ForegroundColor Gray
    Write-Host "4. Navigate to Monitoring or Logs from the navigation" -ForegroundColor Gray
    
} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
}