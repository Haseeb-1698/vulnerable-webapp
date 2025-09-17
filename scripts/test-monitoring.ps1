# Test Monitoring Endpoints
Write-Host "Testing Monitoring Endpoints" -ForegroundColor Cyan

try {
    # Login first
    $loginBody = '{"email":"alice@example.com","password":"password123"}'
    $response = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -UseBasicParsing
    $loginData = $response.Content | ConvertFrom-Json
    $token = $loginData.token
    Write-Host "Login successful" -ForegroundColor Green
    
    $headers = @{ "Authorization" = "Bearer $token" }
    
    # Test health endpoint (no auth required)
    Write-Host "`nTesting health endpoint..." -ForegroundColor Yellow
    try {
        $healthResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/monitoring/health" -UseBasicParsing
        Write-Host "Health endpoint: OK" -ForegroundColor Green
    } catch {
        Write-Host "Health endpoint: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Test dashboard endpoint
    Write-Host "`nTesting dashboard endpoint..." -ForegroundColor Yellow
    try {
        $dashboardResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/monitoring/dashboard" -Headers $headers -UseBasicParsing
        $dashboardData = $dashboardResponse.Content | ConvertFrom-Json
        Write-Host "Dashboard endpoint: OK" -ForegroundColor Green
        Write-Host "  Performance data: $($dashboardData.data.performance -ne $null)" -ForegroundColor White
        Write-Host "  Security data: $($dashboardData.data.security -ne $null)" -ForegroundColor White
        Write-Host "  Audit data: $($dashboardData.data.audit -ne $null)" -ForegroundColor White
    } catch {
        Write-Host "Dashboard endpoint: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Test audit endpoint
    Write-Host "`nTesting audit endpoint..." -ForegroundColor Yellow
    try {
        $auditResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/monitoring/audit" -Headers $headers -UseBasicParsing
        $auditData = $auditResponse.Content | ConvertFrom-Json
        Write-Host "Audit endpoint: OK" -ForegroundColor Green
        Write-Host "  Audit entries: $($auditData.data.Count)" -ForegroundColor White
    } catch {
        Write-Host "Audit endpoint: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Test performance endpoint
    Write-Host "`nTesting performance endpoint..." -ForegroundColor Yellow
    try {
        $perfResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/monitoring/performance" -Headers $headers -UseBasicParsing
        Write-Host "Performance endpoint: OK" -ForegroundColor Green
    } catch {
        Write-Host "Performance endpoint: FAILED - $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`nMonitoring endpoints test completed!" -ForegroundColor Cyan
    
} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
}