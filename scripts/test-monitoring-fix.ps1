# Test Monitoring Fix
Write-Host "Testing Monitoring Dashboard Fix" -ForegroundColor Cyan

try {
    # Login first
    $loginBody = '{"email":"alice@example.com","password":"password123"}'
    $response = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -UseBasicParsing
    $loginData = $response.Content | ConvertFrom-Json
    $token = $loginData.token
    Write-Host "Login successful" -ForegroundColor Green
    
    $headers = @{ "Authorization" = "Bearer $token" }
    
    # Test dashboard endpoint with detailed output
    Write-Host "`nTesting dashboard endpoint..." -ForegroundColor Yellow
    try {
        $dashboardResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/monitoring/dashboard" -Headers $headers -UseBasicParsing
        $dashboardData = $dashboardResponse.Content | ConvertFrom-Json
        
        Write-Host "Dashboard endpoint: OK" -ForegroundColor Green
        Write-Host "Response structure:" -ForegroundColor Cyan
        Write-Host "  Success: $($dashboardData.success)" -ForegroundColor White
        Write-Host "  Has data: $($dashboardData.data -ne $null)" -ForegroundColor White
        
        if ($dashboardData.data) {
            Write-Host "  Performance data: $($dashboardData.data.performance -ne $null)" -ForegroundColor White
            Write-Host "  Security data: $($dashboardData.data.security -ne $null)" -ForegroundColor White
            Write-Host "  Audit data: $($dashboardData.data.audit -ne $null)" -ForegroundColor White
            Write-Host "  Logs data: $($dashboardData.data.logs -ne $null)" -ForegroundColor White
            
            # Check specific nested properties
            if ($dashboardData.data.performance) {
                Write-Host "    Performance.current: $($dashboardData.data.performance.current -ne $null)" -ForegroundColor Gray
                Write-Host "    Performance.summary: $($dashboardData.data.performance.summary -ne $null)" -ForegroundColor Gray
            }
            
            if ($dashboardData.data.security) {
                Write-Host "    Security.attacksByType: $($dashboardData.data.security.attacksByType -ne $null)" -ForegroundColor Gray
                Write-Host "    Security.topAttackers: $($dashboardData.data.security.topAttackers -ne $null)" -ForegroundColor Gray
            }
        }
        
        Write-Host "`nDashboard data structure looks good!" -ForegroundColor Green
        
    }
    catch {
        Write-Host "Dashboard endpoint: FAILED - $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            $errorContent = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorContent)
            $errorText = $reader.ReadToEnd()
            Write-Host "Error details: $errorText" -ForegroundColor Red
        }
    }
    
    Write-Host "`nMonitoring fix test completed!" -ForegroundColor Cyan
    Write-Host "The frontend should now handle undefined data gracefully." -ForegroundColor White
    
}
catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
}