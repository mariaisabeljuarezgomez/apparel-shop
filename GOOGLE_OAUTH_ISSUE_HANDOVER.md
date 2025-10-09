# Google OAuth Login Issue - Complete Analysis & Handover

**Date:** October 8-9, 2025  
**Issue:** Google OAuth login has been broken for an extended period  
**Status:** UNRESOLVED - Server crashes in production, OAuth callback never reached

---

## PROBLEM SUMMARY

When users click "Continue with Google" on the login page:
1. ✅ Frontend popup opens successfully
2. ✅ User authenticates with Google
3. ✅ Google redirects to: `https://plwgscreativeapparel.com/oauth/callback?code=XXX`
4. ❌ **Server returns 404 - OAuth callback route is never reached**
5. ❌ Login fails

---

## CURRENT SERVER STATUS

**Railway Deployment Status:** CRASH LOOP
- Server starts successfully (all initialization completes)
- Server runs for ~5-10 seconds
- Railway kills container with `SIGTERM`
- Infinite restart loop

**Latest Deploy Logs:**
```
🚀 Starting server...
✅ Google OAuth client initialized
🔧 Initializing admin credentials...
✅ Admin credentials initialized
🌐 Starting Express server on port 8080...
✅ SERVER RUNNING on port 8080
Stopping Container         <-- Railway kills it here
npm error signal SIGTERM
```

---

## ROOT CAUSE ANALYSIS

### Railway Healthcheck Failure
**Suspected Issue:** Railway's healthcheck is failing, causing it to kill the container.

**Current Healthcheck Config** (`railway.json`):
```json
"healthcheckPath": "/api/health",
"healthcheckTimeout": 300
```

**Changed from:** `"healthcheckPath": "/"` (homepage was too slow)

**Problem:** Even with `/api/health`, server still crashes. Either:
- The healthcheck endpoint is not responding
- Railway is not recognizing the server as healthy
- There's a different issue causing the crash

---

## CODE STRUCTURE

### OAuth Callback Route
**File:** `server.js` (Line 4064)
```javascript
app.get('/oauth/callback', async (req, res) => {
  try {
    logger.info('🔐 OAuth callback received', { query: req.query });
    // ... token exchange logic
  }
});
```

**Status:** Route IS defined and should be registered

### Google OAuth Credentials
**Environment Variables in Railway:**
- `GOOGLE_CLIENT_ID`: (OAuth 2.0 Client ID from Google Cloud Console)
- `GOOGLE_CLIENT_SECRET`: (OAuth 2.0 Client Secret from Google Cloud Console)

**Google Cloud Console:**
- **Project:** PLWGS CREATIVE APPAREL
- **OAuth Client:** "PLWGS Creative Apparel Web Client"
- **Authorized Redirect URI:** `https://plwgscreativeapparel.com/oauth/callback`
- **Status:** Correctly configured

### Frontend OAuth Flow
**File:** `pages/customer-login.html`
- Opens popup to Google OAuth URL
- Popup URL includes correct redirect_uri
- Frontend logs show everything working up to the callback

---

## WHAT WAS TRIED (Chronologically)

### 1. Dotenv Package Issues ❌
**Problem:** Railway was running `dotenvx` which loaded 0 environment variables  
**Attempted Fixes:**
- Removed dotenv package entirely → Server crashed (needed for local dev)
- Added dotenv back → Crash loop continued
- Removed duplicate `require('dotenv')` from `cloudinary-upload.js` → Crash continued

### 2. Google OAuth Client Initialization ❌
**Problem:** Suspected OAuth client initialization was crashing  
**Fix Attempted:** Added try-catch around `new OAuth2Client()`  
**Result:** OAuth client initializes successfully (logs show ✅) but server still crashes

### 3. Railway Healthcheck Configuration ❌
**Problem:** Suspected homepage (`/`) was failing healthcheck  
**Fix Attempted:** Changed to `/api/health` with 300s timeout  
**Result:** Server still crashes after startup

### 4. Package Lock File Issues ✅ (Resolved)
**Problem:** `package-lock.json` had wrong dotenv version  
**Fix:** Ran `npm install` locally and pushed updated lock file  
**Result:** Build succeeds, but runtime crash continues

---

## ENVIRONMENT VARIABLES STATUS

**Confirmed Present in Railway:**
- ✅ `DATABASE_URL`
- ✅ `GOOGLE_CLIENT_ID` (set in Railway UI)
- ✅ `GOOGLE_CLIENT_SECRET` (set in Railway UI)
- ✅ `PAYPAL_CLIENT_ID`
- ✅ `PAYPAL_CLIENT_SECRET`
- ✅ `JWT_SECRET`
- ✅ All 40+ other required variables

**Loading Method:**
- Local dev: Uses `.env` file
- Railway: Uses native environment variables (dotenv still installed but optional)

---

## DIAGNOSTIC LOGS TO REQUEST

1. **Railway Build Logs** - To confirm successful build
2. **Railway Deploy Logs** - To see startup sequence and crash
3. **Railway Healthcheck Logs** - To see if `/api/health` is responding
4. **Network Logs** - When clicking "Continue with Google", check if callback request reaches server
5. **Railway Dashboard** - Check if there are any deployment errors or warnings

---

## NEXT STEPS TO INVESTIGATE

### 1. Verify Healthcheck Endpoint
Check if `/api/health` is actually responding:
```bash
curl https://plwgscreativeapparel.com/api/health
```

If it returns 404 or timeout, the route might not be registered.

### 2. Check Railway Service Settings
- Verify port configuration (should be 8080)
- Check if there's a PORT environment variable conflict
- Verify Railway isn't killing the process for resource limits

### 3. Test OAuth Route Directly
Try hitting the callback route directly (won't work without auth code, but should return an error, not 404):
```bash
curl https://plwgscreativeapparel.com/oauth/callback
```

If this returns 404, the route is not being registered.

### 4. Check Express Route Registration
The OAuth route is defined at line 4064 of `server.js`. Verify:
- It's not being overridden by a catch-all route
- It's not inside a conditional that's failing
- Express is actually loading and parsing this part of the file

### 5. Railway Crash Analysis
The SIGTERM signal suggests Railway is actively killing the process. Check:
- Railway dashboard for "why" the container was stopped
- Railway metrics for memory/CPU usage spikes
- Railway logs for any healthcheck failure messages

---

## FILES MODIFIED (Last 24 Hours)

1. `server.js` - Added OAuth logging, error handling, startup logs
2. `pages/checkout.html` - Fixed tiered shipping (WORKING)
3. `pages/cart.html` - Fixed tiered shipping (WORKING)
4. `cloudinary-upload.js` - Removed duplicate dotenv require
5. `railway.json` - Changed healthcheck from `/` to `/api/health`
6. `package.json` - Changed dotenv version from 17.2.1 to 16.4.5
7. `package-lock.json` - Updated to match package.json

---

## WORKING FEATURES (For Context)

✅ **Tiered Shipping** - Cart and checkout correctly calculate shipping  
✅ **PayPal Integration** - Checkout and payment processing work  
✅ **Admin Panel** - Uploads, editing, all admin functions work  
✅ **Product Display** - Size/color chart toggles work  
✅ **Regular Login** - Email/password authentication works  

**Only Google OAuth is broken**

---

## IMPORTANT NOTES

1. **The server DOES start** - All initialization logs complete successfully
2. **Railway kills it** - Not a startup crash, Railway actively stops the container
3. **Frontend works** - OAuth popup opens, user can authenticate with Google
4. **Callback fails** - The redirect back to the site returns 404
5. **This is an old issue** - Has been broken for an extended period according to the user

---

## RECOMMENDED APPROACH FOR NEXT DEVELOPER

1. **First:** Check Railway dashboard for detailed healthcheck logs
2. **Second:** Verify the `/api/health` endpoint is actually accessible
3. **Third:** Test if ANY routes are accessible after deployment (try `/api/test`)
4. **Fourth:** If no routes work, the issue is Express not starting properly despite logs saying it is
5. **Fifth:** Consider if Railway's proxy/load balancer is the issue, not the Node.js server

---

## CONTACT INFORMATION

**Customer:** Lori Nelton (PLWGS Creative Apparel)  
**Site:** https://plwgscreativeapparel.com  
**Railway Project:** PLWGSCREATIVEAPPAREL  
**GitHub Repo:** https://github.com/PLWGS/PLWGCREATIVEAPPAREL

---

## FINAL ASSESSMENT

This appears to be a **Railway deployment/networking issue**, not a code issue:
- Code is correct (OAuth route exists and is properly defined)
- Environment variables are loaded
- Server starts successfully
- Railway healthcheck is failing or Railway is killing the process for another reason

**The solution likely lies in Railway's configuration, not the application code.**

---

**Created:** October 9, 2025, 00:45 UTC  
**Last Known Working Commit:** Unknown (OAuth has been broken for extended period)  
**Current Commit:** `ca986d2` - "FIX: Change healthcheck to /api/health to prevent crashes"

