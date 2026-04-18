/**
 * Trigger IP blocking by sending rapid requests to /api/data
 * This endpoint has firewall middleware applied
 */

const http = require('http');

const options = {
    hostname: 'localhost',
    port: 4000,
    path: '/api/data',  // This endpoint has firewall middleware!
    method: 'GET',
    timeout: 200
};

let sentCount = 0;
let blockedCount = 0;
let completedCount = 0;

function sendRequest() {
    return new Promise((resolve) => {
        const req = http.request(options, (res) => {
            sentCount++;
            
            // Check for rate limit response (429)
            if (res.statusCode === 429) {
                blockedCount++;
                console.log(`[429 RATE LIMITED] Request ${sentCount}`);
            }
            
            // Consume response data
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                completedCount++;
                if (sentCount % 20 === 0) {
                    console.log(`Progress: ${sentCount} sent, ${blockedCount} blocked (429)`);
                }
                resolve();
            });
        });
        
        req.on('error', (err) => {
            sentCount++;
            completedCount++;
            resolve();
        });
        
        req.setTimeout(300, () => {
            req.destroy();
            sentCount++;
            completedCount++;
            resolve();
        });
        
        req.end();
    });
}

async function triggerBlock() {
    console.log('='.repeat(60));
    console.log('TRIGGERING IP BLOCK VIA /api/data ENDPOINT');
    console.log('='.repeat(60));
    console.log('Target: 170+ requests to exceed rate limit (150 threshold)');
    console.log('Expected: Should see many 429 responses\n');
    
    const startTime = Date.now();
    
    // Send 170 requests rapidly
    for (let i = 0; i < 170; i++) {
        sendRequest();
        // No delay - maximum speed
    }
    
    // Wait for all to complete
    await new Promise(resolve => {
        const checkInterval = setInterval(() => {
            if (completedCount >= 170) {
                clearInterval(checkInterval);
                resolve();
            }
        }, 100);
        setTimeout(() => {
            clearInterval(checkInterval);
            resolve();
        }, 10000);
    });
    
    const elapsed = Date.now() - startTime;
    
    console.log('\n' + '='.repeat(60));
    console.log('RESULTS AFTER BOMBARDMENT');
    console.log('='.repeat(60));
    console.log(`Requests sent: ${sentCount}`);
    console.log(`Rate limit (429) responses: ${blockedCount}`);
    console.log(`Time elapsed: ${elapsed}ms`);
    console.log(`Requests completed: ${completedCount}`);
    
    if (blockedCount > 0) {
        console.log('\n✅ RATE LIMITING IS WORKING! Saw 429 responses.');
    } else {
        console.log('\n⚠  No 429 responses yet. IP may not have hit threshold.');
    }
    
    // Now check if IP is in blocked list
    console.log('\n' + '='.repeat(60));
    console.log('CHECKING BLOCKED IPS');
    console.log('='.repeat(60));
    
    const checkOpts = {
        hostname: 'localhost',
        port: 4000,
        path: '/api/blocked-ips',
        method: 'GET'
    };
    
    const checkReq = http.request(checkOpts, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
            try {
                const json = JSON.parse(body);
                if (json.data && json.data.length > 0) {
                    console.log('✅ SUCCESS! IPs are blocked:');
                    json.data.forEach(entry => {
                        console.log(`  - ${entry.ip}: ${entry.reason}`);
                    });
                } else {
                    console.log('❌ No IPs blocked yet.');
                }
            } catch (e) {
                console.log('Error parsing response:', e.message);
            }
            process.exit(0);
        });
    });
    
    checkReq.on('error', err => {
        console.error('Check failed:', err.message);
        process.exit(1);
    });
    
    checkReq.end();
}

triggerBlock().catch(err => {
    console.error('Error:', err);
    process.exit(1);
});

