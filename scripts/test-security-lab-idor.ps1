# Test Security Lab IDOR endpoint
Write-Host "Testing Security Lab IDOR endpoint" -ForegroundColor Red

try {
    # Login as Alice
    $loginBody = '{"email":"alice@example.com","password":"password123"}'
    $response = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -UseBasicParsing
    $loginData = $response.Content | ConvertFrom-Json
    $token = $loginData.token
    Write-Host "Login successful" -ForegroundColor Green
    
    # Test IDOR through security lab endpoint
    $headers = @{ 
        "Authorization" = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    $testBody = @{
        payload = "123"
        target = ""
    } | ConvertTo-Json
    
    $idorTestResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/security-lab/vulnerabilities/idor/test" -Method Post -Body $testBody -Headers $headers -UseBasicParsing
    $idorResult = $idorTestResponse.Content | ConvertFrom-Json
    
    Write-Host "IDOR Test Result:" -ForegroundColor Cyan
    Write-Host "  Result: $($idorResult.result)" -ForegroundColor $(if ($idorResult.result -eq 'VULNERABLE') { 'Red' } else { 'Green' })
    Write-Host "  Attack Succeeded: $($idorResult.attackSucceeded)" -ForegroundColor White
    Write-Host "  Description: $($idorResult.description)" -ForegroundColor Yellow
    
    if ($idorResult.result -eq 'VULNERABLE') {
        Write-Host "IDOR vulnerability confirmed through security lab!" -ForegroundColor Red
    } else {
        Write-Host "IDOR test result: $($idorResult.result)" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Response) {
        $errorContent = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorContent)
        $errorText = $reader.ReadToEnd()
        Write-Host "Error details: $errorText" -ForegroundColor Red
    }
}