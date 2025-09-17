# Test Security Lab IDOR endpoint with existing task
Write-Host "Testing Security Lab IDOR with existing task" -ForegroundColor Red

try {
    # Login as Alice
    $loginBody = '{"email":"alice@example.com","password":"password123"}'
    $response = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json" -UseBasicParsing
    $loginData = $response.Content | ConvertFrom-Json
    $token = $loginData.token
    Write-Host "Alice login successful" -ForegroundColor Green
    
    # Get Alice's tasks to find an existing task ID
    $headers = @{ "Authorization" = "Bearer $token" }
    $tasksResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/tasks" -Headers $headers -UseBasicParsing
    $tasks = ($tasksResponse.Content | ConvertFrom-Json).tasks
    
    if ($tasks.Count -gt 0) {
        # Use an existing task ID + 1 to test IDOR
        $existingTaskId = $tasks[0].id
        $testTaskId = $existingTaskId + 1
        
        Write-Host "Testing IDOR with task ID: $testTaskId (existing task + 1)" -ForegroundColor Cyan
        
        # Test IDOR through security lab endpoint
        $testHeaders = @{ 
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        }
        
        $testBody = @{
            payload = $testTaskId.ToString()
            target = ""
        } | ConvertTo-Json
        
        $idorTestResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/security-lab/vulnerabilities/idor/test" -Method Post -Body $testBody -Headers $testHeaders -UseBasicParsing
        $idorResult = $idorTestResponse.Content | ConvertFrom-Json
        
        Write-Host "IDOR Test Result:" -ForegroundColor Cyan
        Write-Host "  Result: $($idorResult.result)" -ForegroundColor $(if ($idorResult.result -eq 'VULNERABLE') { 'Red' } elseif ($idorResult.result -eq 'SECURE') { 'Green' } else { 'Yellow' })
        Write-Host "  Attack Succeeded: $($idorResult.attackSucceeded)" -ForegroundColor White
        Write-Host "  Description: $($idorResult.description)" -ForegroundColor Yellow
        
        if ($idorResult.result -eq 'VULNERABLE') {
            Write-Host "IDOR vulnerability confirmed!" -ForegroundColor Red
        }
    } else {
        Write-Host "No tasks found to test with" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
}