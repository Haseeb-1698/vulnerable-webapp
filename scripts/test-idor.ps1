# IDOR Testing Script
Write-Host "Testing IDOR Vulnerability" -ForegroundColor Red

try {
    # Login as Alice
    $aliceLogin = '{"email":"alice@example.com","password":"password123"}'
    $aliceResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/login" -Method Post -Body $aliceLogin -ContentType "application/json" -UseBasicParsing
    $aliceData = $aliceResponse.Content | ConvertFrom-Json
    $aliceToken = $aliceData.token
    Write-Host "Alice login successful" -ForegroundColor Green
    
    # Login as Bob
    $bobLogin = '{"email":"bob@example.com","password":"password123"}'
    $bobResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/auth/login" -Method Post -Body $bobLogin -ContentType "application/json" -UseBasicParsing
    $bobData = $bobResponse.Content | ConvertFrom-Json
    $bobToken = $bobData.token
    Write-Host "Bob login successful" -ForegroundColor Green
    
    # Get Alice's tasks
    $aliceHeaders = @{ "Authorization" = "Bearer $aliceToken" }
    $aliceTasksResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/tasks" -Headers $aliceHeaders -UseBasicParsing
    $aliceTasks = ($aliceTasksResponse.Content | ConvertFrom-Json).tasks
    
    # Get Bob's tasks  
    $bobHeaders = @{ "Authorization" = "Bearer $bobToken" }
    $bobTasksResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/tasks" -Headers $bobHeaders -UseBasicParsing
    $bobTasks = ($bobTasksResponse.Content | ConvertFrom-Json).tasks
    
    Write-Host "Alice has $($aliceTasks.Count) tasks" -ForegroundColor Cyan
    Write-Host "Bob has $($bobTasks.Count) tasks" -ForegroundColor Cyan
    
    if ($aliceTasks.Count -gt 0 -and $bobTasks.Count -gt 0) {
        # Try to access Bob's task using Alice's token (IDOR attack)
        $bobTaskId = $bobTasks[0].id
        $bobTaskTitle = $bobTasks[0].title
        
        Write-Host "Attempting IDOR: Alice trying to access Bob's task $bobTaskId" -ForegroundColor Yellow
        
        try {
            $idorResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/tasks/$bobTaskId" -Headers $aliceHeaders -UseBasicParsing
            $idorData = $idorResponse.Content | ConvertFrom-Json
            
            if ($idorResponse.StatusCode -eq 200) {
                Write-Host "IDOR VULNERABILITY CONFIRMED!" -ForegroundColor Red
                Write-Host "Alice successfully accessed Bob's task: '$bobTaskTitle'" -ForegroundColor Red
                Write-Host "Task owner: $($idorData.task.user.firstName) $($idorData.task.user.lastName)" -ForegroundColor Yellow
                
                if ($idorData.ownership) {
                    Write-Host "Ownership info:" -ForegroundColor Cyan
                    Write-Host "  Task Owner ID: $($idorData.ownership.taskOwnerId)" -ForegroundColor White
                    Write-Host "  Request User ID: $($idorData.ownership.requestUserId)" -ForegroundColor White
                    Write-Host "  Is Owner: $($idorData.ownership.isOwner)" -ForegroundColor White
                }
            }
        } catch {
            if ($_.Exception.Response.StatusCode -eq 403) {
                Write-Host "IDOR blocked: Access forbidden (403)" -ForegroundColor Green
            } elseif ($_.Exception.Response.StatusCode -eq 404) {
                Write-Host "Task not found (404)" -ForegroundColor Yellow
            } else {
                Write-Host "IDOR test failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        # Also test the reverse - Bob accessing Alice's task
        if ($aliceTasks.Count -gt 0) {
            $aliceTaskId = $aliceTasks[0].id
            $aliceTaskTitle = $aliceTasks[0].title
            
            Write-Host "Attempting reverse IDOR: Bob trying to access Alice's task $aliceTaskId" -ForegroundColor Yellow
            
            try {
                $reverseIdorResponse = Invoke-WebRequest -Uri "http://localhost:3001/api/tasks/$aliceTaskId" -Headers $bobHeaders -UseBasicParsing
                
                if ($reverseIdorResponse.StatusCode -eq 200) {
                    Write-Host "Reverse IDOR also successful!" -ForegroundColor Red
                    Write-Host "Bob accessed Alice's task: '$aliceTaskTitle'" -ForegroundColor Red
                }
            } catch {
                Write-Host "Reverse IDOR blocked or failed" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "Not enough tasks to test IDOR" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
}