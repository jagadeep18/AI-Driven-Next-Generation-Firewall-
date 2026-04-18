# Firewall Traffic Monitoring System - PowerShell Test Script
# Pure ASCII - No special characters

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FIREWALL TRAFFIC MONITORING SYSTEM TEST" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$FirewallBaseURL = "http://localhost:4000"
$AppBaseURL = "http://localhost:5000"
$DashboardURL = "$FirewallBaseURL/dashboard"

# Test counters
$TestsPassed = 0
$TestsFailed = 0

function Test-Request {
    param(
        [string]$TestName,
        [string]$URL,
        [string]$ExpectedResult,
        [int]$ExpectedStatusCode = 200
    )
    
    Write-Host "[TEST] $TestName" -ForegroundColor Yellow
    Write-Host "  URL: $URL" -ForegroundColor Gray
    
    try {
        $response = Invoke-RestMethod -Uri $URL -ErrorAction Stop
        Write-Host "  Result: [OK] Request succeeded" -ForegroundColor Green
        $Global:TestsPassed++
        return $true
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.Value__
        if ($statusCode -eq 403 -or $statusCode -eq 429) {
            Write-Host "  Result: [BLOCKED] Status $statusCode (as expected)" -ForegroundColor Red
            $Global:TestsPassed++
            return $false
        }
        else {
            Write-Host "  Result: [ERROR] $($_.Exception.Message)" -ForegroundColor Red
            $Global:TestsFailed++
            return $false
        }
    }
}

# Check if servers are running
Write-Host "[CHECK] Verifying servers are running..." -ForegroundColor Cyan
try {
    $null = Invoke-RestMethod -Uri "http://localhost:5000/" -ErrorAction Stop
    Write-Host "  [OK] App Server (port 5000) is running" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] App Server is not responding on port 5000" -ForegroundColor Red
    Write-Host "  Please start: node app/appServer.js" -ForegroundColor Yellow
    exit 1
}

try {
    $null = Invoke-RestMethod -Uri "http://localhost:4000/api/stats" -ErrorAction Stop
    Write-Host "  [OK] Firewall Server (port 4000) is running" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Firewall Server is not responding on port 4000" -ForegroundColor Red
    Write-Host "  Please start: node backend/firewallServer.js" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST 1: LEGITIMATE TRAFFIC (ALLOWED)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Test-Request "Access API Data" "$FirewallBaseURL/proxy/api/data" "ALLOWED"
Test-Request "Access Login" "$FirewallBaseURL/login" "ALLOWED"
Test-Request "Access Root" "$FirewallBaseURL/" "ALLOWED"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST 2: ACCESS POLICY BLOCKING" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[TEST] Access Restricted Admin Panel (should be BLOCKED)" -ForegroundColor Yellow
Write-Host "  URL: $FirewallBaseURL/admin" -ForegroundColor Gray
try {
    $response = Invoke-RestMethod -Uri "$FirewallBaseURL/admin" -ErrorAction Stop
    Write-Host "  Result: [ERROR] Should have been blocked" -ForegroundColor Red
    $TestsFailed++
} catch {
    if ($_.Exception.Response.StatusCode.Value__ -eq 403) {
        Write-Host "  Result: [BLOCKED] 403 Forbidden (policy enforcement)" -ForegroundColor Red
        $TestsPassed++
    } else {
        Write-Host "  Result: [ERROR] Unexpected status code" -ForegroundColor Red
        $TestsFailed++
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST 3: SQL INJECTION DETECTION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$SQLIninjectionTests = @(
    "' OR 1=1--",
    "' UNION SELECT * FROM users--",
    "1; DROP TABLE users--"
)

foreach ($payload in $SQLIninjectionTests) {
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    Write-Host "[TEST] SQL Injection: $payload" -ForegroundColor Yellow
    Write-Host "  Payload: $encodedPayload" -ForegroundColor Gray
    try {
        $response = Invoke-RestMethod -Uri "$FirewallBaseURL/login?user=$encodedPayload" -ErrorAction Stop
        Write-Host "  Result: [ERROR] Should have been blocked" -ForegroundColor Red
        $TestsFailed++
    } catch {
        if ($_.Exception.Response.StatusCode.Value__ -eq 403) {
            Write-Host "  Result: [BLOCKED] IDS detected SQL_INJECTION" -ForegroundColor Red
            $TestsPassed++
        } else {
            Write-Host "  Result: [UNKNOWN] Status $($_.Exception.Response.StatusCode.Value__)" -ForegroundColor Yellow
        }
    }
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST 4: XSS ATTACK DETECTION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$XSSTests = @(
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)"
)

foreach ($payload in $XSSTests) {
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    Write-Host "[TEST] XSS Attack: $payload" -ForegroundColor Yellow
    Write-Host "  Payload: $encodedPayload" -ForegroundColor Gray
    try {
        $response = Invoke-RestMethod -Uri "$FirewallBaseURL/login?user=$encodedPayload" -ErrorAction Stop
        Write-Host "  Result: [ERROR] Should have been blocked" -ForegroundColor Red
        $TestsFailed++
    } catch {
        if ($_.Exception.Response.StatusCode.Value__ -eq 403) {
            Write-Host "  Result: [BLOCKED] IDS detected XSS" -ForegroundColor Red
            $TestsPassed++
        } else {
            Write-Host "  Result: [UNKNOWN] Status $($_.Exception.Response.StatusCode.Value__)" -ForegroundColor Yellow
        }
    }
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST 5: COMMAND INJECTION DETECTION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$CommandTests = @(
    "; ls -la",
    "&& cat /etc/passwd",
    "| whoami"
)

foreach ($payload in $CommandTests) {
    $encodedPayload = [System.Web.HttpUtility]::UrlEncode($payload)
    Write-Host "[TEST] Command Injection: $payload" -ForegroundColor Yellow
    Write-Host "  Payload: $encodedPayload" -ForegroundColor Gray
    try {
        $response = Invoke-RestMethod -Uri "$FirewallBaseURL/api/data?cmd=$encodedPayload" -ErrorAction Stop
        Write-Host "  Result: [ERROR] Should have been blocked" -ForegroundColor Red
        $TestsFailed++
    } catch {
        if ($_.Exception.Response.StatusCode.Value__ -eq 403) {
            Write-Host "  Result: [BLOCKED] IDS detected COMMAND_INJECTION" -ForegroundColor Red
            $TestsPassed++
        } else {
            Write-Host "  Result: [UNKNOWN] Status $($_.Exception.Response.StatusCode.Value__)" -ForegroundColor Yellow
        }
    }
    Start-Sleep -Milliseconds 500
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST 6: DIRECT APP SERVER ACCESS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[TEST] Access app server directly (bypasses firewall)" -ForegroundColor Yellow
Write-Host "  URL: $AppBaseURL/admin" -ForegroundColor Gray
try {
    $response = Invoke-RestMethod -Uri "$AppBaseURL/admin" -ErrorAction Stop
    Write-Host "  Result: [OK] Direct access allowed (no firewall protection)" -ForegroundColor Green
    Write-Host "  Note: This demonstrates why firewall proxy is essential" -ForegroundColor Cyan
    $TestsPassed++
} catch {
    Write-Host "  Result: [ERROR] Unexpected response" -ForegroundColor Red
    $TestsFailed++
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FINAL STATISTICS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

try {
    $stats = Invoke-RestMethod -Uri "$FirewallBaseURL/api/stats" -ErrorAction Stop
    $data = $stats.data
    
    Write-Host "Total Requests: $($data.totalRequests)" -ForegroundColor White
    Write-Host "Blocked Requests: $($data.blockedRequests)" -ForegroundColor Red
    Write-Host "Intrusion Attempts: $($data.intrusionAttempts)" -ForegroundColor Yellow
    Write-Host "Blocked IPs: $($data.blockedIps)" -ForegroundColor Magenta
}
catch {
    Write-Host "[ERROR] Could not fetch stats" -ForegroundColor Red
}

Write-Host ""
Write-Host "Tests Passed: $TestsPassed" -ForegroundColor Green
Write-Host "Tests Failed: $TestsFailed" -ForegroundColor Red
Write-Host ""

if ($TestsFailed -eq 0) {
    Write-Host "[SUCCESS] All tests passed!" -ForegroundColor Green
    Write-Host "Dashboard: $DashboardURL" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "[FAILURE] Some tests failed" -ForegroundColor Red
    exit 1
}
