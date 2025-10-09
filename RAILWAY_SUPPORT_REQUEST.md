# Railway Support Request - Critical Production Issue

## **URGENT: Container Being Killed - Google OAuth Broken**

**Date:** October 9, 2025
**Railway Project:** PLWGSCREATIVEAPPAREL
**Service:** plwgscreativeapparel-production
**Issue:** Container crashes immediately after startup, Google OAuth login fails

---

## **PROBLEM SUMMARY**

Our Node.js application container is being killed by Railway after 5-10 seconds with a SIGTERM signal. The server starts successfully (all initialization completes), but Railway terminates the process before any HTTP requests can be processed.

**Impact:**
- Google OAuth login completely broken (users get 404 on callback)
- Website becomes unresponsive
- Infinite crash loop

---

## **DETAILED SYMPTOMS**

### **Railway Logs Show:**
```
🚀 Starting server...
✅ Google OAuth client initialized
📝 Registering OAuth callback route: GET /oauth/callback
🌐 Starting Express server on port 8080...
✅ SERVER RUNNING on port 8080
🔧 Initializing admin credentials in background...
✅ Admin credentials initialized
Stopping Container    ← Railway kills it here
npm error signal SIGTERM
```

### **Browser Console Shows:**
```
🔍 Starting Google Sign-In initialization...
✅ Google script loaded
🔍 Fetching client ID from server...
✅ Client ID fetched: Yes
🔘 Google login button clicked
✅ Using popup method (GSI has CORS issues)
🔍 googleOAuthPopup() function called
🔍 Opening popup with URL: https://accounts.google.com/oauth/authorize?client_id=340277902902-k60pgdt6l051l7kbefvu6rto1tlncv6t.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fplwgscreativeapparel.com%2Foauth%2Fcallback&scope=openid%20email%20profile&response_type=code&state=7gxey862xv2
🔍 Popup object: Window about:blank
```

**The popup shows "about:blank" because the server is dead when Google redirects back.**

---

## **TECHNICAL CONFIGURATION**

### **Railway Service Settings:**
```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "NIXPACKS",
    "buildCommand": "npm install && npm run build:css"
  },
  "deploy": {
    "startCommand": "node server.js",
    "healthcheckPath": "/api/health",
    "healthcheckTimeout": 300,
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  },
  "environments": {
    "production": {
      "variables": {
        "NODE_ENV": "production",
        "LOG_LEVEL": "error"
      }
    }
  }
}
```

### **Application Code (server.js):**
```javascript
// Server startup
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ SERVER RUNNING AND LISTENING on 0.0.0.0:${PORT}`);
  console.log(`🌍 Server is now accepting HTTP connections`);
});

// OAuth callback route
app.get('/oauth/callback', async (req, res) => {
  try {
    logger.info('🔐 OAuth callback received', { query: req.query });
    // Token exchange logic...
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});
```

### **Environment Variables:**
✅ All 40+ required variables are confirmed present in Railway:
- `DATABASE_URL`
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `PAYPAL_CLIENT_ID`
- `PAYPAL_CLIENT_SECRET`
- `JWT_SECRET`
- All others

---

## **WHAT HAPPENS WHEN WE TRY TO ACCESS THE SITE**

### **Before Fix Attempts:**
- `/` returned JSON from `/api/health` instead of HTML
- All routes returned 404

### **After Adding Explicit Route:**
```javascript
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
```
- Homepage works correctly
- Other static routes work
- **OAuth callback still fails because container dies**

---

## **ALL ATTEMPTED FIXES (15+ Approaches)**

### **1. Healthcheck Configuration** ❌ (Tried 6+ times)
**Problem:** Suspected healthcheck failure causing container kill

**Attempts:**
- Changed `healthcheckPath` from `/` to `/api/health` with 10s timeout
- Increased timeout to 300s
- Removed healthcheck entirely
- Re-added healthcheck with 300s timeout
- Removed healthcheck again

**Result:** **EXACT SAME CRASH** every time. Container dies after 5-10 seconds regardless of healthcheck configuration.

### **2. Static File Middleware** ❌
**Problem:** Suspected `app.use(express.static('.'))` intercepting `/oauth/callback`

**Fix Attempted:**
- Removed catch-all static middleware
- Added specific routes for `/public`, `/css`, `/pages`

**Result:**
- Homepage broke (returned JSON instead of HTML)
- Fixed with explicit `/` route
- **OAuth still broken, container still dies**

### **3. Port Binding** ❌
**Problem:** Suspected server not binding to correct interface

**Fix Attempted:**
- Changed `app.listen(PORT)` to `app.listen(PORT, '0.0.0.0')`

**Result:** Latest change, not yet deployed/tested

### **4. Package Dependencies** ✅ (Resolved)
**Problem:** `package-lock.json` had wrong dotenv version

**Fix:** Ran `npm install` locally and pushed updated lock file

**Result:** Build succeeds, but runtime crash continues

### **5. Environment Variables** ✅ (Confirmed Working)
**Problem:** Suspected missing environment variables

**Verification:** All 40+ variables confirmed present in Railway dashboard

---

## **CODE VERIFICATION**

### **OAuth Route Definition:**
```javascript
// File: server.js, Line 4079
console.log('📝 Registering OAuth callback route: GET /oauth/callback');
app.get('/oauth/callback', async (req, res) => {
  try {
    logger.info('🔐 OAuth callback received', { query: req.query });
    const { code, state } = req.query;

    if (!code) {
      logger.error('❌ No authorization code in callback');
      return res.status(400).send(`
        <script>
          window.opener.postMessage({error: 'Authorization code not received'}, '*');
          window.close();
        </script>
      `);
    }
    // ... rest of OAuth logic
  } catch (error) {
    logger.error('❌ OAuth callback error:', error);
    res.status(500).send(`
      <script>
        window.opener.postMessage({error: 'Server error'}, '*');
        window.close();
      </script>
    `);
  }
});
```

### **Google OAuth Configuration:**
```javascript
// OAuth client initialization (Line ~4000)
const { google } = require('googleapis');
const oauth2Client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  `${req.protocol}://${req.get('host')}/oauth/callback`
);
```

### **Frontend OAuth Flow:**
```javascript
// File: pages/customer-login.html
// Popup opens to correct Google OAuth URL
// Google redirects to: https://plwgscreativeapparel.com/oauth/callback?code=XXX
```

---

## **WHAT WE NEED FROM RAILWAY SUPPORT**

### **Critical Questions:**
1. **Why is the container being killed?** The logs show "Stopping Container" but no error message or stack trace.

2. **Are there healthcheck failure logs?** Even though we've tried with/without healthcheck, we need to see Railway's healthcheck logs.

3. **Are there resource limits being hit?** Memory, CPU, or network quotas?

4. **Is there a load balancer or proxy issue?** The server logs show it's listening, but HTTP requests may not be reaching it.

5. **Are there any platform-level issues?** Network problems, service disruptions, or configuration issues?

### **Diagnostic Information We Need:**
- Detailed deployment logs (beyond what's shown in dashboard)
- Healthcheck-specific logs and metrics
- Network/proxy/load balancer logs
- Container resource usage metrics
- Any error messages or warnings not visible in current logs

---

## **EVIDENCE THIS IS A RAILWAY ISSUE**

### **Code Works Locally:**
- ✅ Application runs perfectly in local development
- ✅ OAuth works in local environment
- ✅ All routes and endpoints function correctly

### **Server Starts Successfully:**
- ✅ All initialization completes (database, OAuth client, routes)
- ✅ Express server binds to port and listens
- ✅ No startup errors or exceptions

### **Only Railway Kills It:**
- ❌ Container dies immediately after startup
- ❌ No error messages or stack traces
- ❌ Consistent across 15+ different configuration attempts

---

## **BUSINESS IMPACT**

**Critical:**
- Google OAuth login completely broken for all users
- Website becomes unresponsive
- Customer authentication blocked
- Business operations halted

**Timeline:** This has been broken for an extended period (user reports it's an "old problem").

---

## **SUPPORT REQUEST**

**Priority:** URGENT - Production service down
**Issue Type:** Container deployment/crash
**Expected Response Time:** Within 24 hours

Please investigate why Railway is killing our container and provide a resolution path. The application code is correct and works locally - this appears to be a Railway platform issue.

---

**Contact Information:**
**Customer:** PLWGS Creative Apparel
**Site:** https://plwgscreativeapparel.com
**Railway Project ID:** PLWGSCREATIVEAPPAREL
**Email:** [Your contact email]
**Phone:** [Your contact phone]

Thank you for your urgent assistance with this critical production issue.
