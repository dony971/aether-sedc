Write-Host "Stopping all AETHER nodes..." -ForegroundColor Yellow
Get-Process -Name "aether" -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "  Stopping PID $($_.Id)..." -NoNewline
    $_.Kill()
    Write-Host " DONE" -ForegroundColor Green
}
Write-Host "All nodes stopped." -ForegroundColor Green
