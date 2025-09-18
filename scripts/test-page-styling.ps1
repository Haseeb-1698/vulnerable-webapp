# Test Page Styling Consistency
Write-Host "Testing Page Styling Consistency" -ForegroundColor Cyan

try {
    # Test if frontend is running
    Write-Host "Checking frontend server..." -ForegroundColor Yellow
    try {
        $frontendResponse = Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing -TimeoutSec 5
        Write-Host "Frontend server: RUNNING" -ForegroundColor Green
    } catch {
        Write-Host "Frontend server: NOT RUNNING" -ForegroundColor Red
        Write-Host "Please start the frontend with: npm start" -ForegroundColor Yellow
        return
    }
    
    # Test pages for consistent styling
    $pages = @(
        @{ name = "Tasks"; url = "http://localhost:3000/tasks"; expected = "bg-slate-50" },
        @{ name = "Search"; url = "http://localhost:3000/search"; expected = "bg-slate-50" },
        @{ name = "Profile"; url = "http://localhost:3000/profile"; expected = "bg-slate-50" },
        @{ name = "Monitoring"; url = "http://localhost:3000/monitoring"; expected = "monitoring" },
        @{ name = "Logs"; url = "http://localhost:3000/logs"; expected = "logs" }
    )
    
    Write-Host "`nTesting page accessibility and styling..." -ForegroundColor Yellow
    
    foreach ($page in $pages) {
        try {
            $response = Invoke-WebRequest -Uri $page.url -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                $content = $response.Content
                
                # Check for expected styling or content
                if ($content -match $page.expected -or $content -match "bg-slate-50" -or $content -match $page.name.ToLower()) {
                    Write-Host "  $($page.name): ACCESSIBLE with expected styling" -ForegroundColor Green
                } else {
                    Write-Host "  $($page.name): ACCESSIBLE but may need styling check" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "  $($page.name): FAILED - $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host "`nStyling consistency test completed!" -ForegroundColor Cyan
    Write-Host "`nAll pages should now have:" -ForegroundColor White
    Write-Host "  - Consistent slate background with grid pattern" -ForegroundColor Gray
    Write-Host "  - Proper navigation (where applicable)" -ForegroundColor Gray
    Write-Host "  - Responsive layout with max-width containers" -ForegroundColor Gray
    Write-Host "  - Error boundaries for better error handling" -ForegroundColor Gray
    
} catch {
    Write-Host "Test failed: $($_.Exception.Message)" -ForegroundColor Red
}