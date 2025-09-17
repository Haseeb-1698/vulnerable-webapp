# Session Management Vulnerability Testing Script
Write-Host "Testing Session Management Vulnerabilities" -ForegroundColor Red

try {
    # Login to get a token
    $loginBody = '{"email":"alice@example.com","password":"password123"}'
    $response = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -UseBasicParsing
    $loginData = $response.Content | ConvertFrom-Json
    $token = $loginData.token
    Write-Host "Login successful, token obtained" -ForegroundColor Green
    
    Write-Host "`n=== Session Management Vulnerability Tests ===" -ForegroundColor Yellow
    
    # Test 1: Check if session info is exposed
    Write-Host "`n1. Testing Session Info Exposure..." -ForegroundColor Cyan
    try {
        $sessionInfoResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/session-info" -UseBasicParsing
        $sessionInfo = $sessionInfoResponse.Content | ConvertFrom-Json
        
        Write-Host "VULNERABLE: Session info endpoint exposed!" -ForegroundColor Red
        Write-Host "  JWT Secret: $($sessionInfo.jwtConfig.secret)" -ForegroundColor Yellow
        Write-Host "  Expiration: $($sessionInfo.jwtConfig.expiresIn)" -ForegroundColor Yellow
        Write-Host "  Vulnerabilities found: $($sessionInfo.vulnerabilities.Count)" -ForegroundColor Yellow
    } catch {
        Write-Host "SECURE: Session info endpoint not accessible" -ForegroundColor Green
    }
    
    # Test 2: Check token validation endpoint
    Write-Host "`n2. Testing Token Validation Secret Exposure..." -ForegroundColor Cyan
    try {
        $validateBody = @{ token = $token } | ConvertTo-Json
        $validateResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/validate" -Method Post -Body $validateBody -ContentType "application/json" -UseBasicParsing
        $validateData = $validateResponse.Content | ConvertFrom-Json
        
        if ($validateData.tokenDetails.secret) {
            Write-Host "VULNERABLE: JWT secret exposed in validation!" -ForegroundColor Red
            Write-Host "  Exposed Secret: $($validateData.tokenDetails.secret)" -ForegroundColor Yellow
        } else {
            Write-Host "SECURE: JWT secret not exposed in validation" -ForegroundColor Green
        }
    } catch {
        Write-Host "Token validation test failed or endpoint not accessible" -ForegroundColor Yellow
    }
    
    # Test 3: Check logout token invalidation
    Write-Host "`n3. Testing Logout Token Invalidation..." -ForegroundColor Cyan
    $headers = @{ "Authorization" = "Bearer $token" }
    
    # First, verify token works
    try {
        $meResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/me" -Headers $headers -UseBasicParsing
        Write-Host "Token valid before logout" -ForegroundColor Green
        
        # Logout
        $logoutResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/logout" -Method Post -Headers $headers -UseBasicParsing
        $logoutData = $logoutResponse.Content | ConvertFrom-Json
        
        if ($logoutData.tokenInfo.stillValid) {
            Write-Host "VULNERABLE: Token still valid after logout!" -ForegroundColor Red
            Write-Host "  Warning: $($logoutData.warning)" -ForegroundColor Yellow
        }
        
        # Try to use token after logout
        try {
            $meAfterLogout = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/me" -Headers $headers -UseBasicParsing
            Write-Host "VULNERABLE: Token still works after logout!" -ForegroundColor Red
        } catch {
            Write-Host "SECURE: Token invalidated after logout" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "Initial token validation failed" -ForegroundColor Yellow
    }
    
    # Test 4: Client-side token decoding
    Write-Host "`n4. Testing Client-side Token Decoding..." -ForegroundColor Cyan
    try {
        $tokenParts = $token.Split('.')
        if ($tokenParts.Count -eq 3) {
            # Decode the payload (middle part)
            $payloadBase64 = $tokenParts[1]
            # Add padding if needed
            while ($payloadBase64.Length % 4 -ne 0) {
                $payloadBase64 += "="
            }
            
            $payloadBytes = [System.Convert]::FromBase64String($payloadBase64)
            $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
            $payload = $payloadJson | ConvertFrom-Json
            
            Write-Host "VULNERABLE: JWT payload decoded client-side!" -ForegroundColor Red
            Write-Host "  User ID: $($payload.userId)" -ForegroundColor Yellow
            Write-Host "  Email: $($payload.email)" -ForegroundColor Yellow
            Write-Host "  Expires: $(Get-Date -UnixTimeSeconds $payload.exp)" -ForegroundColor Yellow
            Write-Host "  Role: $($payload.role)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Failed to decode token payload" -ForegroundColor Yellow
    }
    
    # Test 5: Test through security lab endpoint
    Write-Host "`n5. Testing via Security Lab Endpoint..." -ForegroundColor Cyan
    try {
        $testHeaders = @{ 
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        }
        
        $testBody = @{
            payload = "Decode JWT token client-side"
            target = ""
        } | ConvertTo-Json
        
        $sessionTestResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/security-lab/vulnerabilities/sessionManagement/test" -Method Post -Body $testBody -Headers $testHeaders -UseBasicParsing
        $sessionResult = $sessionTestResponse.Content | ConvertFrom-Json
        
        Write-Host "Security Lab Result: $($sessionResult.result)" -ForegroundColor $(if ($sessionResult.result -eq 'VULNERABLE') { 'Red' } else { 'Green' })
        Write-Host "Attack Succeeded: $($sessionResult.attackSucceeded)" -ForegroundColor White
        Write-Host "Description: $($sessionResult.description)" -ForegroundColor Yellow
        
        if ($sessionResult.actualResponse.vulnerabilities) {
            Write-Host "`nDetailed Vulnerabilities:" -ForegroundColor Cyan
            foreach ($vuln in $sessionResult.actualResponse.vulnerabilities) {
                Write-Host "  - $vuln" -ForegroundColor Red
            }
        }
        
        if ($sessionResult.actualResponse.testResults) {
            Write-Host "`nTest Results:" -ForegroundColor Cyan
            foreach ($test in $sessionResult.actualResponse.testResults) {
                $color = switch ($test.result) {
                    'VULNERABLE' { 'Red' }
                    'SECURE' { 'Green' }
                    default { 'Yellow' }
                }
                Write-Host "  $($test.test): $($test.result)" -ForegroundColor $color
                Write-Host "    $($test.details)" -ForegroundColor Gray
            }
        }
        
    } catch {
        Write-Host "Security lab test failed: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "`n=== Summary ===" -ForegroundColor Yellow
    Write-Host "Session management testing completed. Check results above for vulnerabilities." -ForegroundColor White
    
} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
}