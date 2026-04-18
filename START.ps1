# AI-NGFW Security Command Center - Startup Script
Write-Host ""
Write-Host " =====================================================" -ForegroundColor Cyan
Write-Host "  AI-NGFW SECURITY COMMAND CENTER - STARTUP" -ForegroundColor Cyan
Write-Host " =====================================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $PSScriptRoot

Write-Host "[1/2] Installing dependencies (if needed)..." -ForegroundColor Yellow
npm install --silent

Write-Host "[2/2] Starting Firewall Server..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Dashboard : http://localhost:4000/dashboard" -ForegroundColor Green
Write-Host "  Firewall  : http://localhost:4000" -ForegroundColor Green
Write-Host ""

npm run start-firewall
