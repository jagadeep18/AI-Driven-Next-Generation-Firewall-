# Firewall Traffic Monitoring System - Demo Guide

## TABLE OF CONTENTS
1. [Starting the Application](#starting-the-application)
2. [Accessing the Dashboard](#accessing-the-dashboard)
3. [Testing Scenarios](#testing-scenarios)
4. [Network Testing (Multi-Device)](#network-testing-multi-device)
5. [Understanding the Dashboard](#understanding-the-dashboard)

---

## STARTING THE APPLICATION

### Start Both Servers

**Terminal 1: Application Server**
```bash
node app/appServer.js
```
[OK] Application Server runs on **port 5000**

**Terminal 2: Firewall Server**
```bash
node backend/firewallServer.js
```
[OK] Firewall Server runs on **port 4000**

> **Note:** Keep both terminals running during the demo.

---

## ACCESSING THE DASHBOARD

Open your browser and navigate to:
```
http://localhost:4000/dashboard
```

You'll see the **Firewall Management Center** with:
- 4 stat cards (Total Requests, Blocked, Intrusions, Blocked IPs)
- 4 tabs (Traffic Logs, Intrusion Logs, Audit Logs, Blocked IPs)
- Auto-refresh every 5 seconds

---

## TESTING SCENARIOS

### Test 1: Legitimate Traffic [PASS]

**PowerShell:**
```powershell
# Access API through firewall proxy
Invoke-RestMethod http://localhost:4000/proxy/api/data

# Access login page
Invoke-RestMethod http://localhost:4000/login
```

**Browser:**
```
http://localhost:4000/proxy/api/data
```

**Expected Result:**
- [OK] Request is ALLOWED
- Traffic Logs shows green "ALLOW" badge
- Total Requests counter increases
- Data is returned successfully

---

### Test 2: Access Policy Blocking [BLOCK]

**PowerShell:**
```powershell
# Try to access restricted /admin endpoint
Invoke-RestMethod http://localhost:4000/admin
```

**Browser:**
```
http://localhost:4000/admin
```

**Expected Result:**
- [BLOCKED] 403 Forbidden error
- Dashboard shows:
  - Blocked Requests counter increases
  - Traffic Logs shows red "BLOCK" badge
  - Reason: "Admin access restricted by firewall policy"

---

### Test 3: SQL Injection Attack [ALERT_HIGH]

**PowerShell:**
```powershell
# SQL injection with OR bypass
Invoke-RestMethod "http://localhost:4000/login?user=' OR 1=1--"

# SQL injection with UNION SELECT
Invoke-RestMethod "http://localhost:4000/login?user=' UNION SELECT * FROM users--"

# SQL injection with DROP TABLE
Invoke-RestMethod "http://localhost:4000/api/data?id=1; DROP TABLE users--"
```

**Browser:**
```
http://localhost:4000/login?user=' OR 1=1--
http://localhost:4000/login?user=' UNION SELECT password FROM users--
```

**Expected Result:**
- [INTRUSION] Request BLOCKED by Intrusion Detection System
- **Intrusion Logs tab** shows:
  - Attack Type: **SQL_INJECTION**
  - Severity: **HIGH**
  - Your IP address
  - Target endpoint
- Intrusion Attempts counter increases

---

### Test 4: Cross-Site Scripting (XSS) [ALERT_HIGH]

**PowerShell:**
```powershell
# XSS with script tag
Invoke-RestMethod "http://localhost:4000/login?user=<script>alert('hacked')</script>"

# XSS with event handler
Invoke-RestMethod "http://localhost:4000/login?user=<img src=x onerror=alert(1)>"

# XSS with javascript: URI
Invoke-RestMethod "http://localhost:4000/api/data?redirect=javascript:alert(document.cookie)"
```

**Browser:**
```
http://localhost:4000/login?user=<script>alert('XSS')</script>
http://localhost:4000/api/data?name=<img src=x onerror=alert(1)>
```

**Expected Result:**
- [INTRUSION] Request BLOCKED by IDS
- **Intrusion Logs** shows:
  - Attack Type: **XSS**
  - Severity: **HIGH**

---

### Test 5: Command Injection [ALERT_HIGH]

**PowerShell:**
```powershell
# Command injection with semicolon
Invoke-RestMethod "http://localhost:4000/api/data?cmd=; ls -la"

# Command injection with AND operator
Invoke-RestMethod "http://localhost:4000/login?user=admin && cat /etc/passwd"

# Command injection with pipe
Invoke-RestMethod "http://localhost:4000/api/data?file=test.txt | rm -rf /"
```

**Browser:**
```
http://localhost:4000/api/data?cmd=; ls
http://localhost:4000/login?user=admin && whoami
```

**Expected Result:**
- [INTRUSION] Request BLOCKED by IDS
- **Intrusion Logs** shows:
  - Attack Type: **COMMAND_INJECTION**
  - Severity: **HIGH**

---

### Test 6: Rate Limiting [THROTTLE]

**PowerShell:**
```powershell
# Send 105 requests (exceeds 100/min limit)
1..105 | ForEach-Object { 
    try {
        Invoke-RestMethod http://localhost:4000/login -ErrorAction Stop
        Write-Host "Request $_ - OK" -ForegroundColor Green
    } catch {
        Write-Host "Request $_ - BLOCKED (Rate Limit)" -ForegroundColor Red
    }
}
```

**Expected Result:**
- [OK] First ~100 requests succeed
- [BLOCKED] Requests 101+ return **429 Too Many Requests**
- Dashboard shows blocked requests increasing
- After 150+ excessive requests, IP may be auto-blocked

---

### Test 7: Direct Application Access (Bypassing Firewall)

**PowerShell:**
```powershell
# Access app server directly (bypasses firewall)
Invoke-RestMethod http://localhost:5000/admin
```

**Browser:**
```
http://localhost:5000/admin
```

**Expected Result:**
- [OK] Access GRANTED (no firewall protection)
- Shows the danger of exposing app server directly
- Demonstrates why firewall proxy is essential

---

## NETWORK TESTING (Multi-Device)

### Step 1: Find Your IP Address

**Windows:**
```powershell
ipconfig
# Look for IPv4 Address (e.g., 192.168.1.100)
```

**Linux/Mac:**
```bash
ifconfig
# or
ip addr show
```

### Step 2: Test from Another Device

From a phone, tablet, or another laptop on the **same WiFi network**:

**Access Dashboard:**
```
http://192.168.1.100:4000/dashboard
```

**Send Normal Request:**
```
http://192.168.1.100:4000/proxy/api/data
```

**Send Attack:**
```
http://192.168.1.100:4000/login?user=' OR 1=1--
```

**Expected Result:**
- Dashboard shows the **external device's IP** in logs
- All firewall rules apply to network traffic
- Real-world network monitoring demonstration

---

## UNDERSTANDING THE DASHBOARD

### Overview Cards

1. **Total Requests**
   - Counts all HTTP requests (allowed + blocked)
   - Updates in real-time

2. **Blocked Requests**
   - Requests blocked by access policies or IDS
   - Shows firewall effectiveness

3. **Intrusion Attempts**
   - Attack patterns detected by IDS
   - Indicates security threats

4. **Blocked IPs**
   - IPs permanently blocked (manual or auto-blocked)
   - After repeated rate limit violations

### Dashboard Tabs

#### 1. Traffic Logs
- **IP Address** - Source of the request
- **Endpoint** - Target URL path
- **Method** - HTTP verb (GET, POST, etc.)
- **Action** - ALLOW (green) or BLOCK (red)
- **Time** - When the request occurred

#### 2. Intrusion Logs
- **IP Address** - Attacker's IP
- **Attack Type** - SQL_INJECTION, XSS, COMMAND_INJECTION
- **Target Endpoint** - What they tried to attack
- **Severity** - Always HIGH for detected attacks
- **Time** - Detection timestamp

#### 3. Audit Logs
- System events:
  - Firewall server started
  - Database initialized
  - Rate limit violations
  - IP auto-blocks
- Provides system activity timeline

#### 4. Blocked IPs
- **IP Address** - Blocked IP
- **Reason** - Why it was blocked
- **Time** - When the block occurred

---

## QUICK 60-SECOND DEMO SCRIPT

Copy and paste this into PowerShell for a rapid demo:

```powershell
# Open dashboard
Start-Process "http://localhost:4000/dashboard"
Start-Sleep -Seconds 2

# 1. Legitimate traffic [OK]
Write-Host "`n=== Test 1: Legitimate Request ===" -ForegroundColor Cyan
Invoke-RestMethod http://localhost:4000/proxy/api/data
Write-Host "[OK] Allowed" -ForegroundColor Green
Start-Sleep -Seconds 1

# 2. Access policy block [BLOCK]
Write-Host "`n=== Test 2: Admin Access (Policy Block) ===" -ForegroundColor Cyan
try { Invoke-RestMethod http://localhost:4000/admin } catch { }
Write-Host "[BLOCKED] By Access Policy" -ForegroundColor Red
Start-Sleep -Seconds 1

# 3. SQL injection [ALERT]
Write-Host "`n=== Test 3: SQL Injection Attack ===" -ForegroundColor Cyan
try { Invoke-RestMethod "http://localhost:4000/login?user=' OR 1=1--" } catch { }
Write-Host "[ALERT] Blocked by IDS - SQL_INJECTION" -ForegroundColor Magenta
Start-Sleep -Seconds 1

# 4. XSS attack [ALERT]
Write-Host "`n=== Test 4: XSS Attack ===" -ForegroundColor Cyan
try { Invoke-RestMethod "http://localhost:4000/login?user=<script>alert(1)</script>" } catch { }
Write-Host "[ALERT] Blocked by IDS - XSS" -ForegroundColor Magenta
Start-Sleep -Seconds 1

# 5. Check stats
Write-Host "`n=== Final Dashboard Stats ===" -ForegroundColor Cyan
$stats = Invoke-RestMethod http://localhost:4000/api/stats
Write-Host "Total Requests: $($stats.data.totalRequests)" -ForegroundColor White
Write-Host "Blocked: $($stats.data.blockedRequests)" -ForegroundColor Red
Write-Host "Intrusions: $($stats.data.intrusionAttempts)" -ForegroundColor Yellow

Write-Host "`n[DONE] Demo Complete! Check the dashboard for detailed logs." -ForegroundColor Green
```

---

## TROUBLESHOOTING

### Port Already in Use
```powershell
# Check what's using the port
netstat -ano | findstr ":4000"

# Kill the process (replace PID)
taskkill /PID <PID> /F
```

### Database Not Updating
- Database auto-saves every 3 seconds
- Check `database/logs.db` file exists
- Restart the firewall server

### Dashboard Not Loading
- Verify firewall server is running
- Check port 4000 is listening: `netstat -ano | findstr ":4000"`
- Try: `http://127.0.0.1:4000/dashboard`

---

## TEST CHECKLIST

Use this checklist during your demo:

- [ ] Both servers started successfully
- [ ] Dashboard loads at http://localhost:4000/dashboard
- [ ] Legitimate request shows as ALLOWED
- [ ] /admin blocked by access policy
- [ ] SQL injection detected and blocked
- [ ] XSS attack detected and blocked
- [ ] Command injection detected and blocked
- [ ] Traffic logs populated
- [ ] Intrusion logs show attack details
- [ ] Audit logs show system events
- [ ] Stats cards update correctly
- [ ] Network access tested from another device
- [ ] Rate limiting triggers after 100 requests

---

## DEMO TIPS

1. **Open dashboard first** - Show the empty state, then generate traffic
2. **Use browser + PowerShell** - Show attacks from different sources
3. **Refresh dashboard between tests** - Let audience see updates
4. **Explain the pipeline** - Blocked IP -> Rate Limit -> Policy -> IDS -> Logger
5. **Show the database file** - Prove persistence with `database/logs.db`
6. **Test from mobile** - Most impressive for network demo
7. **Explain color coding** - Green=ALLOW, Red=BLOCK, badges for attack types

---

## ADDITIONAL RESOURCES

- **Project Structure**: See folder organization in root directory
- **Firewall Rules**: Check `backend/firewallMiddleware.js` for policy definitions
- **Attack Signatures**: View regex patterns in `backend/intrusionDetector.js`
- **Database Schema**: See table definitions in `backend/database.js`

---

## NEXT STEPS

After the demo, try:
1. Adding custom access policies
2. Creating new attack signatures
3. Implementing permanent IP bans
4. Adding email alerts for intrusions
5. Exporting logs to CSV
6. Building a mobile app dashboard

---

**Built with:** Node.js, Express, SQLite (sql.js), Vanilla JavaScript
**No Docker Required** - Pure JavaScript implementation

Happy Testing! Stay Secure!
