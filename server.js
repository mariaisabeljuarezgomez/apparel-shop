const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { uploadProductImages, uploadImageToCloudinary, deleteImagesFromCloudinary } = require('./cloudinary-upload.js');
const { body, validationResult } = require('express-validator');
const paypal = require('@paypal/checkout-server-sdk');
const { OAuth2Client } = require('google-auth-library');

// Load environment variables
// Railway will have them pre-set, local dev will load from .env
require('dotenv').config();
console.log('🚀 Starting server...');

// Initialize Google OAuth client
let googleClient;
try {
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    googleClient = new OAuth2Client(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET
    );
    console.log('✅ Google OAuth client initialized');
  } else {
    console.warn('⚠️  Google OAuth credentials not found - Google login will be disabled');
    googleClient = null;
  }
} catch (error) {
  console.error('❌ Failed to initialize Google OAuth client:', error.message);
  googleClient = null;
}

// -----------------------------------------------------------------------------
// Timeout Configuration - Fix request aborted errors
// -----------------------------------------------------------------------------
const serverTimeout = 300000; // 5 minutes for server timeout
const requestTimeout = 120000; // 2 minutes for request timeout
const uploadTimeout = 180000; // 3 minutes for image uploads

// -----------------------------------------------------------------------------
// Logging Configuration - Reduce Railway log verbosity
// -----------------------------------------------------------------------------
const isProduction = process.env.NODE_ENV === 'production';
const isRailway = process.env.RAILWAY_ENVIRONMENT === 'production' || process.env.RAILWAY_PROJECT_ID;
const LOG_LEVEL = process.env.LOG_LEVEL || (isProduction || isRailway ? 'error' : 'info');

// Custom logger to control verbosity - EXTREMELY restrictive for Railway
const logger = {
  info: (...args) => {
    // In Railway, only log critical info
    if (LOG_LEVEL === 'info' || LOG_LEVEL === 'debug') {
      if (!isRailway || LOG_LEVEL === 'debug') {
        console.log(...args);
      }
    }
  },
  warn: (...args) => {
    // In Railway, only log critical warnings
    if (LOG_LEVEL === 'warn' || LOG_LEVEL === 'info' || LOG_LEVEL === 'debug') {
      if (!isRailway || LOG_LEVEL === 'debug') {
        console.warn(...args);
      }
    }
  },
  error: (...args) => {
    // Always log errors, but limit frequency in Railway
    if (isRailway) {
      // Rate limit errors in Railway to prevent rate limiting
      if (!logger.error.lastLog || Date.now() - logger.error.lastLog > 1000) {
        console.error(...args);
        logger.error.lastLog = Date.now();
      }
    } else {
      console.error(...args);
    }
  },
  debug: (...args) => {
    if (LOG_LEVEL === 'debug') {
      if (!isRailway) {
        console.log('🔍 DEBUG:', ...args);
      }
    }
  }
};

// Log startup configuration
if (!isRailway) {
  logger.info(`🚀 Starting server with LOG_LEVEL: ${LOG_LEVEL}, NODE_ENV: ${process.env.NODE_ENV || 'development'}`);
  if (isRailway) {
    logger.info('🚂 Railway environment detected - logging minimized');
  }
}

// -----------------------------------------------------------------------------
// Railway Logging Suppression - Prevent other libraries from logging
// -----------------------------------------------------------------------------
if (isRailway) {
  // Less aggressive logging suppression for Railway
  const originalWarn = console.warn;
  const originalInfo = console.info;
  const originalDebug = console.debug;

  // Only suppress verbose warnings and info, keep errors and our logs
  console.warn = (...args) => {
    // Only show critical warnings
    if (args[0] && typeof args[0] === 'string' && args[0].includes('❌')) {
      originalWarn(...args);
    }
  };

  console.info = (...args) => {
    // Suppress info logs but keep our important messages
    if (args[0] && typeof args[0] === 'string' && (
      args[0].includes('✅') ||
      args[0].includes('🚀') ||
      args[0].includes('🔧') ||
      args[0].includes('🎉')
    )) {
      originalInfo(...args);
    }
  };

  console.debug = (...args) => {
    // Suppress debug logs completely
  };

}

// -----------------------------------------------------------------------------
// Schema Generation Functions for SEO
// -----------------------------------------------------------------------------

/**
 * Generate enhanced product schema markup for SEO
 * Includes your Etsy review data (755 reviews, 4.9 rating) for competitive advantage
 */
function generateProductSchema(product, reviews) {
  const baseUrl = process.env.BASE_URL || 'https://plwgscreativeapparel.com';
  
  // Use Etsy review data for maximum SEO impact
  const etsyReviewCount = 755;
  const etsyRating = 4.9;
  
  // Use product reviews if available, otherwise fall back to Etsy data
  const reviewCount = reviews.count > 0 ? reviews.count : etsyReviewCount;
  const rating = reviews.average > 0 ? reviews.average : etsyRating;
  
  const schema = {
    "@context": "https://schema.org",
    "@type": "Product",
    "name": product.name,
    "description": product.description || `Custom ${product.category || 't-shirt'} with professional DTG printing`,
    "image": product.image_url ? [product.image_url] : [],
    "brand": {
      "@type": "Brand",
      "name": "PLWGS Creative Apparel"
    },
    "manufacturer": {
      "@type": "Organization",
      "name": "PLWGS Creative Apparel",
      "url": baseUrl
    },
    "offers": {
      "@type": "Offer",
      "price": product.price || 22.00,
      "priceCurrency": "USD",
      "availability": product.stock_quantity > 0 ? "https://schema.org/InStock" : "https://schema.org/OutOfStock",
      "seller": {
        "@type": "Organization",
        "name": "PLWGS Creative Apparel",
        "url": baseUrl
      },
      "priceValidUntil": new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]
    },
    "aggregateRating": {
      "@type": "AggregateRating",
      "ratingValue": rating.toFixed(1),
      "reviewCount": reviewCount,
      "bestRating": "5",
      "worstRating": "1"
    },
    "additionalProperty": [
      {
        "@type": "PropertyValue",
        "name": "Printing Method",
        "value": "DTG (Direct-to-Garment)"
      },
      {
        "@type": "PropertyValue", 
        "name": "Material",
        "value": product.specifications?.material || "100% Cotton"
      },
      {
        "@type": "PropertyValue",
        "name": "Custom Design",
        "value": "Available"
      }
    ],
    "category": product.category || "Custom T-Shirts",
    "keywords": [
      "custom t-shirt printing",
      "design your own shirt", 
      "DTG printing",
      "custom t-shirts online",
      "personalized t-shirts"
    ]
  };

  // Add individual reviews if available
  if (reviews.items && reviews.items.length > 0) {
    schema.review = reviews.items.slice(0, 5).map(review => ({
      "@type": "Review",
      "author": {
        "@type": "Person",
        "name": review.display_name || "Customer"
      },
      "reviewRating": {
        "@type": "Rating",
        "ratingValue": review.rating,
        "bestRating": "5",
        "worstRating": "1"
      },
      "reviewBody": review.body || review.title || "Great product!",
      "datePublished": review.created_at
    }));
  }

  return schema;
}

/**
 * Generate business/organization schema with Etsy review data
 */
function generateBusinessSchema() {
  const baseUrl = process.env.BASE_URL || 'https://plwgscreativeapparel.com';
  
  return {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "PLWGS Creative Apparel",
    "description": "Professional custom t-shirt printing with DTG technology. Design your own shirt or choose from our creative collection.",
    "url": baseUrl,
    "logo": `${baseUrl}/mockups/mockup1.png`,
    "foundingDate": "2021",
    "address": {
      "@type": "PostalAddress",
      "addressCountry": "US"
    },
    "contactPoint": {
      "@type": "ContactPoint",
      "contactType": "Customer Service",
      "email": "admin@plwgscreativeapparel.com"
    },
    "sameAs": [
      "https://www.etsy.com/shop/plwgscreativeapparel"
    ],
    "aggregateRating": {
      "@type": "AggregateRating",
      "ratingValue": "4.9",
      "reviewCount": "755",
      "bestRating": "5",
      "worstRating": "1"
    },
    "serviceType": "Custom T-Shirt Printing",
    "areaServed": "United States"
  };
}

// -----------------------------------------------------------------------------
// Admin credentials bootstrap
// -----------------------------------------------------------------------------
// We keep a single, in-memory, canonical hash so deployments never require
// manually re-generating ADMIN_PASSWORD_HASH. If ADMIN_PASSWORD_HASH is not
// provided, we will hash ADMIN_PASSWORD on startup and use that. This prevents
// frequent invalid-credential issues during redeploys.
let ADMIN_EMAIL_MEMO = null;
let ADMIN_PASSWORD_HASH_MEMO = null;

async function initializeAdminCredentials() {
  try {
    ADMIN_EMAIL_MEMO = process.env.ADMIN_EMAIL || null;

    const envHash = process.env.ADMIN_PASSWORD_HASH;
    const envPassword = process.env.ADMIN_PASSWORD;
    const isDevelopment = (process.env.NODE_ENV || 'development') !== 'production';
    const overrideWithPassword = isDevelopment || process.env.ADMIN_OVERRIDE_PASSWORD === 'true';

    if (overrideWithPassword && envPassword && envPassword.length > 0) {
      // Prefer plain password in development or when explicitly overridden
      ADMIN_PASSWORD_HASH_MEMO = await bcrypt.hash(envPassword, 12);
      logger.info('🔐 Using ADMIN_PASSWORD (hashed at startup)');
    } else if (envHash && envHash.startsWith('$2')) {
      ADMIN_PASSWORD_HASH_MEMO = envHash;
      logger.info('🔐 Using ADMIN_PASSWORD_HASH from environment');
    } else if (envPassword && envPassword.length > 0) {
      ADMIN_PASSWORD_HASH_MEMO = await bcrypt.hash(envPassword, 12);
      logger.info('🔐 Generated admin password hash from ADMIN_PASSWORD');
    } else {
      logger.warn('⚠️ No ADMIN_PASSWORD_HASH or ADMIN_PASSWORD provided. Admin login will fail until one is set.');
    }
  } catch (err) {
    logger.error('❌ Failed to initialize admin credentials:', err);
  }
}

// Fetch active admin password hash. Preference order:
// 1) Database-stored override in admin_settings ('admin_password_hash')
// 2) In-memory memo computed at startup from env
async function getActiveAdminPasswordHash() {
  try {
    if (pool) {
      const result = await pool.query(`
        SELECT value FROM admin_settings WHERE key = 'admin_password_hash' LIMIT 1
      `);
      if (result.rows.length > 0 && result.rows[0].value && result.rows[0].value.startsWith('$2')) {
        return result.rows[0].value;
      }
    }
  } catch (e) {
    logger.error('⚠️ Could not read admin password hash from admin_settings:', e.message);
  }
  return ADMIN_PASSWORD_HASH_MEMO;
}

const app = express();
const PORT = process.env.PORT || 3000;
const FEATURE_STATIC_PRODUCT_PAGES = String(process.env.FEATURE_STATIC_PRODUCT_PAGES || 'false').toLowerCase() === 'true';

// Configure timeouts to prevent request aborted errors
app.use((req, res, next) => {
  req.setTimeout(requestTimeout);
  res.setTimeout(requestTimeout);
  next();
});

// EARLY TEST ENDPOINT - should work if Express is functioning
app.get('/api/test', (req, res) => {
  res.json({ message: 'API routes are working!', timestamp: new Date().toISOString() });
});

// CSP Test endpoint
app.get('/api/csp-test', (req, res) => {
  res.json({ 
    message: 'CSP Test', 
    headers: req.headers,
    cspHeader: req.get('Content-Security-Policy')
  });
});


// Middleware
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'https://plwgscreativeapparel.com',
      'http://localhost:3000',
      'http://127.0.0.1:3000'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));


// Raw body parser for webhooks
app.use('/api/paypal/webhook', express.raw({ type: 'application/json' }));

// JSON parser with error handling
app.use(express.json({ 
  limit: '50mb',
  strict: false,
  verify: (req, res, buf) => {
    try {
      if (buf && buf.length > 0) {
        JSON.parse(buf);
      }
    } catch (e) {
      logger.error('❌ Malformed JSON detected:', e.message);
      logger.error('❌ Request URL:', req.url);
      logger.error('❌ Request method:', req.method);
      logger.error('❌ Content-Type:', req.get('Content-Type'));
      logger.error('❌ Raw body length:', buf ? buf.length : 'no body');
      logger.error('❌ Raw body preview:', buf ? buf.toString().substring(0, 200) : 'no body');
      // Don't throw error, just log it and let the request continue
      logger.warn('⚠️ Continuing with malformed JSON request');
    }
  }
}));

app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Add compression middleware for better performance
app.use(compression());

// Security Headers Configuration - MUST be before static file serving
app.use((req, res, next) => {
  // Add cache-busting headers to force CSP refresh
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdn.tailwindcss.com", "https://accounts.google.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.tailwindcss.com", "https://www.paypal.com", "https://www.paypalobjects.com", "https://accounts.google.com", "https://apis.google.com"],
      scriptSrcAttr: [
        "'unsafe-hashes'",
        "'sha256-1jAmyYXcRq6zFldLe/GCgIDJBiOONdXjTLgEFMDnDSM='",
        "'sha256-R6AaG80nmkGc9oFSNvZVF7OOo5gLWHC/2y0eOYYohJ8='",
        "'sha256-GMTUiihXfPWngWeq4wqBusQMc3uhwAYGIklr70mSqTc='",
        "'sha256-/l6w0vnC+DN7tMFOiJiEWqLyy8uJoFwM6E0yzhKXRRQ='",
        "'sha256-2rvfFrggTCtyF5WOiTri1gDS8Boibj4Njn0e+VCBmDI='"
      ],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:", "https:", "http:", "blob:"],
      connectSrc: ["'self'", "https://api.paypal.com", "https://api.sandbox.paypal.com", "https://www.paypal.com", "https://www.sandbox.paypal.com", "https://*.paypal.com", "https://*.paypalobjects.com", "https://accounts.google.com"],
      frameSrc: ["'self'", "https://www.paypal.com", "https://www.sandbox.paypal.com"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'self'", "https://www.paypal.com", "https://www.sandbox.paypal.com"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false, // Disable COEP to avoid breaking Cloudinary images
  crossOriginOpenerPolicy: { policy: "same-origin" },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: { policy: "strict-origin-when-cross-origin" }
}));

// DISABLED: app.use(express.static('.')); - This was causing OAuth routes to 404
// Static files should be served from specific directories only
app.use('/public', express.static('public'));
app.use('/css', express.static('css'));
app.use('/pages', express.static('pages'));
// Removed etsy_images static route - now using Cloudinary for image hosting
app.use('/favicon.ico', express.static('public/favicon.ico'));

// Serve admin-login.html
app.get('/admin-login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'admin-login.html'));
});

// Serve sitemap.xml and robots.txt with proper content type
app.get('/sitemap.xml', (req, res) => {
  res.set('Content-Type', 'application/xml');
  res.sendFile(path.join(__dirname, 'sitemap.xml'));
});

app.get('/robots.txt', (req, res) => {
  res.set('Content-Type', 'text/plain');
  res.sendFile(path.join(__dirname, 'robots.txt'));
});

// Serve product.html for product detail pages
app.get('/product.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'product.html'));
});

// Serve checkout.html with explicit CSP headers
app.get('/checkout.html', (req, res) => {
  // Set explicit CSP headers for checkout page
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com https://accounts.google.com; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://www.paypal.com https://www.paypalobjects.com https://accounts.google.com https://apis.google.com; " +
    "script-src-attr 'unsafe-hashes' 'sha256-1jAmyYXcRq6zFldLe/GCgIDJBiOONdXjTLgEFMDnDSM=' 'sha256-R6AaG80nmkGc9oFSNvZVF7OOo5gLWHC/2y0eOYYohJ8=' 'sha256-GMTUiihXfPWngWeq4wqBusQMc3uhwAYGIklr70mSqTc=' 'sha256-/l6w0vnC+DN7tMFOiJiEWqLyy8uJoFwM6E0yzhKXRRQ=' 'sha256-2rvfFrggTCtyF5WOiTri1gDS8Boibj4Njn0e+VCBmDI=' 'sha256-7s2SeAiBOyYK/9QWYmQ6xelnONAgkw/omxu2Lca+qVM='; " +
    "font-src 'self' https://fonts.gstatic.com https://fonts.googleapis.com; " +
    "img-src 'self' data: https: http: blob:; " +
    "connect-src 'self' https://api.paypal.com https://api.sandbox.paypal.com https://www.paypal.com https://www.sandbox.paypal.com https://*.paypal.com https://*.paypalobjects.com https://accounts.google.com; " +
    "frame-src 'self' https://www.paypal.com https://www.sandbox.paypal.com; " +
    "object-src 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self'; " +
    "frame-ancestors 'self' https://www.paypal.com https://www.sandbox.paypal.com; " +
    "upgrade-insecure-requests"
  );
  
  // Add Cross-Origin-Opener-Policy to allow PayPal popups
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
  res.sendFile(path.join(__dirname, 'pages', 'checkout.html'));
});


// Database connection - DISABLED FOR LOCAL DEVELOPMENT
let pool = null;
let databaseAvailable = false;

const LOCAL_DEV_MODE = process.env.NODE_ENV === 'development';
if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
} else {
  logger.warn('🚫 Database URL not configured - using mock data');
}

// Email transporter
// Smarter config: if port is 465, secure is always true.
// Otherwise, respect the environment variable. This prevents common misconfigurations.
// TRIGGERING REDEPLOY: npm warning fixes need to take effect
const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
const smtpSecure = process.env.SMTP_SECURE === 'true';

// Try different Zoho SMTP configurations
const smtpConfigs = [
  { host: 'smtp.zoho.com', port: 587, secure: false, name: 'Zoho TLS' },
  { host: 'smtp.zoho.com', port: 465, secure: true, name: 'Zoho SSL' },
  { host: 'smtp.zoho.eu', port: 587, secure: false, name: 'Zoho EU TLS' },
  { host: 'smtp.zoho.eu', port: 465, secure: true, name: 'Zoho EU SSL' }
];

// Create transporter with first config, will be updated if needed
const transporter = nodemailer.createTransport({
  host: smtpConfigs[0].host,
  port: smtpConfigs[0].port,
  secure: smtpConfigs[0].secure,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD
  },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 10000,
  pool: false
});

// Helper function to check database availability
function checkDatabase() {
  if (!pool) {
    return { available: false, error: 'Database not configured' };
  }
  if (!databaseAvailable) {
    return { available: false, error: 'Database connection failed' };
  }
  return { available: true };
}

// PayPal Configuration
const paypalClientId = process.env.PAYPAL_CLIENT_ID;
const paypalClientSecret = process.env.PAYPAL_CLIENT_SECRET;
const paypalEnvironment = process.env.PAYPAL_ENVIRONMENT || 'sandbox'; // 'sandbox' or 'live'

// PayPal client configuration
let paypalClient = null;
if (paypalClientId && paypalClientSecret) {
  const environment = paypalEnvironment === 'live' 
    ? new paypal.core.LiveEnvironment(paypalClientId, paypalClientSecret)
    : new paypal.core.SandboxEnvironment(paypalClientId, paypalClientSecret);
  
  paypalClient = new paypal.core.PayPalHttpClient(environment);
  logger.info('✅ PayPal client configured for', paypalEnvironment, 'environment');
} else {
  logger.warn('⚠️ PayPal credentials not configured - payment processing disabled');
}

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};
// Initialize database tables
async function initializeDatabase() {
  if (!pool) {
    logger.warn('⚠️ Skipping database initialization - no database connection');
    databaseAvailable = false;
    return;
  }
  
  try {
    // Create subscribers table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscribers (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255),
        subscribed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT true,
        welcome_email_sent BOOLEAN DEFAULT false,
        discount_code_used BOOLEAN DEFAULT false
      )
    `);

    // Create customers table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customers (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255),
        name VARCHAR(255),
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        phone VARCHAR(50),
        birthday DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        loyalty_points INTEGER DEFAULT 0,
        loyalty_tier VARCHAR(50) DEFAULT 'Creative Rebel',
        total_orders INTEGER DEFAULT 0,
        total_spent DECIMAL(10,2) DEFAULT 0.00,
        average_order_value DECIMAL(10,2) DEFAULT 0.00,
        favorite_day_to_shop VARCHAR(20),
        style_consistency VARCHAR(20) DEFAULT 'High',
        most_active_season VARCHAR(20),
        google_id VARCHAR(255),
        profile_picture TEXT,
        email_verified BOOLEAN DEFAULT false
      )
    `);

    // Ensure backward compatibility for older databases (add missing columns if needed)
    try {
      await pool.query(`ALTER TABLE customers ADD COLUMN IF NOT EXISTS birthday DATE`);
    } catch (error) {
      logger.error('Customers: birthday column check failed:', error.message);
    }

    // Create customer_addresses table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_addresses (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
        address_type VARCHAR(50) DEFAULT 'DEFAULT',
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        address_line1 VARCHAR(255),
        address_line2 VARCHAR(255),
        city VARCHAR(100),
        state VARCHAR(100),
        postal_code VARCHAR(20),
        country VARCHAR(100) DEFAULT 'United States',
        is_default BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create customer_preferences table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_preferences (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
        preference_type VARCHAR(50) NOT NULL,
        preference_value TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(customer_id, preference_type)
      )
    `);

    // Create customer_style_profile table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_style_profile (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
        horror_aesthetic_percentage INTEGER DEFAULT 0,
        pop_culture_percentage INTEGER DEFAULT 0,
        humor_sass_percentage INTEGER DEFAULT 0,
        favorite_colors TEXT[],
        preferred_sizes JSONB,
        fit_preference VARCHAR(50) DEFAULT 'Regular Fit',
        length_preference VARCHAR(50) DEFAULT 'Standard',
        satisfaction_rate INTEGER DEFAULT 100,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Ensure a unique index on customer_id to support upsert by customer
    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND indexname = 'idx_customer_style_profile_customer_id'
        ) THEN
          CREATE UNIQUE INDEX idx_customer_style_profile_customer_id ON customer_style_profile(customer_id);
        END IF;
      END$$;
    `);

    // Create wishlist table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS wishlist (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
        product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(customer_id, product_id)
      )
    `);

    // Create product_reviews table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS product_reviews (
        id SERIAL PRIMARY KEY,
        product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
        customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
        order_id INTEGER REFERENCES orders(id) ON DELETE SET NULL,
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        title VARCHAR(120),
        body TEXT,
        images JSONB,
        status VARCHAR(20) DEFAULT 'approved',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (customer_id, product_id)
      )
    `);

    // Create customer_reviews table for homepage Etsy reviews
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_reviews (
        id SERIAL PRIMARY KEY,
        reviewer_name VARCHAR(100) NOT NULL,
        star_rating INTEGER NOT NULL CHECK (star_rating BETWEEN 1 AND 5),
        review_message TEXT NOT NULL,
        date_reviewed VARCHAR(20),
        is_active BOOLEAN DEFAULT true,
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create loyalty_rewards table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS loyalty_rewards (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
        reward_type VARCHAR(100) NOT NULL,
        reward_name VARCHAR(255) NOT NULL,
        points_cost INTEGER NOT NULL,
        is_redeemed BOOLEAN DEFAULT false,
        redeemed_at TIMESTAMP,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create loyalty_points_history table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS loyalty_points_history (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
        points_change INTEGER NOT NULL,
        change_type VARCHAR(50) NOT NULL,
        description TEXT,
        order_id INTEGER REFERENCES orders(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create products table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        original_price DECIMAL(10,2),
        image_url VARCHAR(500),
        category VARCHAR(100),
        subcategory VARCHAR(100),
        tags TEXT[],
        stock_quantity INTEGER DEFAULT 0,
        low_stock_threshold INTEGER DEFAULT 5,
        is_active BOOLEAN DEFAULT true,
        is_featured BOOLEAN DEFAULT false,
        is_on_sale BOOLEAN DEFAULT false,
        sale_percentage INTEGER DEFAULT 0,
        colors JSON,
        sizes JSON,
        specifications JSON,
        features JSON,
        sub_images JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add new columns if they don't exist
    try {
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS colors JSON`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS sizes JSON`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS specifications JSON`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS features JSON`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS sub_images JSON`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS size_stock JSON`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS track_inventory BOOLEAN DEFAULT false`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS brand_preference TEXT`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS feature_rank INTEGER`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS in_featured BOOLEAN DEFAULT false`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS featured_order INTEGER`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_birthday_enabled BOOLEAN DEFAULT false`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_birthday_required BOOLEAN DEFAULT false`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_birthday_fields TEXT`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_birthday_labels TEXT`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_birthday_char_limit INTEGER DEFAULT 250`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_birthday_question TEXT`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_lyrics_enabled BOOLEAN DEFAULT false`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_lyrics_required BOOLEAN DEFAULT false`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_lyrics_fields TEXT`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_lyrics_labels TEXT`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_lyrics_char_limit INTEGER DEFAULT 250`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS custom_lyrics_question TEXT`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS shipping_cost DECIMAL(10,2) DEFAULT 4.50`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS additional_item_shipping DECIMAL(10,2)`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS local_pickup_enabled BOOLEAN DEFAULT true`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS size_chart JSON`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS specs_notes TEXT`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS size_chart_enabled BOOLEAN DEFAULT true`);
      await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS color_chart_enabled BOOLEAN DEFAULT true`);
      
      // Add custom input columns if they don't exist
      await pool.query(`ALTER TABLE order_items ADD COLUMN IF NOT EXISTS custom_input JSONB`);
      await pool.query(`ALTER TABLE cart ADD COLUMN IF NOT EXISTS custom_input JSONB`);
      await pool.query(`ALTER TABLE cart_items ADD COLUMN IF NOT EXISTS custom_input JSONB`);
      
      // Add payment tracking columns if they don't exist
      await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method VARCHAR(50)`);
      await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_id VARCHAR(255)`);
      await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_status VARCHAR(50) DEFAULT 'pending'`);
      await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_details JSONB`);
    } catch (error) {
      logger.error('Some columns may already exist:', error.message);
    }

    // Admin settings key-value store (for admin password hash and flags)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_settings (
        key VARCHAR(100) PRIMARY KEY,
        value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create orders table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        order_number VARCHAR(50) UNIQUE NOT NULL,
        customer_id INTEGER REFERENCES customers(id),
        customer_email VARCHAR(255),
        customer_name VARCHAR(255),
        total_amount DECIMAL(10,2) NOT NULL,
        subtotal DECIMAL(10,2) NOT NULL,
        tax_amount DECIMAL(10,2) DEFAULT 0.00,
        shipping_amount DECIMAL(10,2) DEFAULT 0.00,
        discount_amount DECIMAL(10,2) DEFAULT 0.00,
        discount_code VARCHAR(50),
        status VARCHAR(50) DEFAULT 'pending',
        shipping_address TEXT,
        billing_address TEXT,
        tracking_number VARCHAR(100),
        notes TEXT,
        loyalty_points_earned INTEGER DEFAULT 0,
        loyalty_points_used INTEGER DEFAULT 0,
        payment_method VARCHAR(50),
        payment_id VARCHAR(255),
        payment_status VARCHAR(50) DEFAULT 'pending',
        payment_details JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create order_items table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
        product_id INTEGER,
        product_name VARCHAR(255) NOT NULL,
        quantity INTEGER NOT NULL,
        unit_price DECIMAL(10,2) NOT NULL,
        total_price DECIMAL(10,2) NOT NULL,
        size VARCHAR(10),
        color VARCHAR(50),
        image_url TEXT,
        custom_input JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create cart table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS cart (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
        product_id INTEGER,
        product_name VARCHAR(255) NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        unit_price DECIMAL(10,2) NOT NULL,
        size VARCHAR(50) DEFAULT 'M',
        color VARCHAR(50) DEFAULT 'Black',
        image_url TEXT,
        custom_input JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create cart_items table for better cart management
    await pool.query(`
      CREATE TABLE IF NOT EXISTS cart_items (
        id SERIAL PRIMARY KEY,
        cart_id INTEGER REFERENCES cart(id) ON DELETE CASCADE,
        product_id INTEGER,
        product_name VARCHAR(255) NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        unit_price DECIMAL(10,2) NOT NULL,
        size VARCHAR(50) DEFAULT 'M',
        color VARCHAR(50) DEFAULT 'Black',
        image_url TEXT,
        custom_input JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create custom_requests table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS custom_requests (
        id SERIAL PRIMARY KEY,
        customer_id INTEGER REFERENCES customers(id),
        customer_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        phone VARCHAR(50),
        timeline VARCHAR(100),
        concept_description TEXT NOT NULL,
        style_preferences JSONB,
        product_type VARCHAR(100) NOT NULL,
        quantity VARCHAR(50) NOT NULL,
        size_requirements JSONB,
        color_preferences TEXT,
        budget_range VARCHAR(100) NOT NULL,
        additional_notes TEXT,
        reference_images JSONB,
        status VARCHAR(50) DEFAULT 'pending',
        priority VARCHAR(20) DEFAULT 'normal',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Skip inserting sample products - we want to start fresh
    logger.info('📦 Products table initialized - ready for fresh product uploads');

    logger.info('✅ Database tables initialized successfully');
    databaseAvailable = true;
  } catch (error) {
    logger.error('❌ Error initializing database:', error);
    databaseAvailable = false;
  }
}

// =============================================================================
// AUTHENTICATION ENDPOINTS
// =============================================================================

// In-memory stores for email-based 2FA and password reset tokens
const twoFactorStore = new Map(); // token -> { email, code, expiresAt }
const passwordResetStore = new Map(); // token -> { email, expiresAt }
const customerPasswordResetStore = new Map(); // token -> { email, expiresAt }

function generateNumericCode(length = 6) {
  const max = Math.pow(10, length) - 1;
  const num = crypto.randomInt(0, max + 1);
  return String(num).padStart(length, '0');
}

// Utility function to optimize Cloudinary URLs for better performance
function optimizeCloudinaryUrl(url, width = 400, height = null) {
  if (!url || !url.includes('res.cloudinary.com')) return url;
  
  // Return original URL without transformations to test if that fixes centering
  return url;
}

// Utility function to optimize product data with Cloudinary URLs
function optimizeProductImages(product) {
  if (product.image_url) {
    product.image_url = optimizeCloudinaryUrl(product.image_url, 400, 300);
  }
  if (product.sub_images && Array.isArray(product.sub_images)) {
    product.sub_images = product.sub_images.map(img => 
      typeof img === 'string' ? optimizeCloudinaryUrl(img, 300, 300) : img
    );
  }
  return product;
}

async function sendEmail(to, subject, html) {
  try {
    await sendResendEmail(to, subject, html);
    return true;
  } catch (e) {
    logger.error('❌ Failed to send email:', e.message);
    return false;
  }
}

// Serve index.html at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Admin login
app.post('/api/admin/login',
  body('email').notEmpty().withMessage('Email is required.'),
  body('password').notEmpty().withMessage('Password is required.'),
  async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    logger.debug('🔍 DEBUG LOGIN ATTEMPT:');
    logger.debug('Email provided:', email);
    logger.debug('Password provided:', password ? '[HIDDEN]' : 'undefined');
    logger.debug('ADMIN_EMAIL (active):', ADMIN_EMAIL_MEMO);
    logger.debug('Admin hash available (memo):', ADMIN_PASSWORD_HASH_MEMO ? 'Yes' : 'No');

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Check if admin credentials match
    if (email && ADMIN_EMAIL_MEMO && email.toLowerCase() === ADMIN_EMAIL_MEMO.toLowerCase()) {
      logger.info('✅ Email matches');
      let isValidPassword = false;

      // Prefer DB-stored admin hash if present
      const activeHash = await getActiveAdminPasswordHash();
      if (activeHash) {
        try {
          isValidPassword = await bcrypt.compare(password, activeHash);
        } catch (e) {
          logger.error('❌ Error during bcrypt.compare for admin login:', e.message);
        }
      } else if (ADMIN_PASSWORD_HASH_MEMO) {
        try {
          isValidPassword = await bcrypt.compare(password, ADMIN_PASSWORD_HASH_MEMO);
        } catch (e) {
          logger.error('❌ Error during bcrypt.compare for admin login:', e.message);
        }
      }

      // Fallback: if a plain ADMIN_PASSWORD is provided and hash compare failed,
      // allow direct comparison as an emergency measure to prevent lockouts.
      if (!isValidPassword && process.env.ADMIN_PASSWORD) {
        if (password === process.env.ADMIN_PASSWORD) {
          isValidPassword = true;
          logger.warn('⚠️ Using plain ADMIN_PASSWORD fallback. Please set ADMIN_PASSWORD_HASH or keep ADMIN_PASSWORD stable.');
        }
      }

      logger.info('🔐 Password check result:', isValidPassword);
      
      if (isValidPassword) {
        // TOTP gate (Google Authenticator) enabled by default unless disabled
        const admin2faEnabled = (process.env.ADMIN_2FA_ENABLED || 'true').replace(/"/g, '').toLowerCase();
        const totpEnabled = admin2faEnabled !== 'false';
        
        // REMOVED: Emergency fallback - forcing proper TOTP authentication
        if (totpEnabled) {
          // Check if TOTP is configured
          const totpSecret = totpSecrets.get('admin');
          if (totpSecret) {
            // TOTP is configured, require it
            return res.json({ totpRequired: true });
          } else {
            // TOTP not configured - require setup before allowing login
            logger.warn('⚠️ TOTP not configured - requiring setup');
            return res.status(403).json({ 
              error: 'TOTP authentication required but not configured. Please setup Google Authenticator.',
              requiresSetup: true,
              setupUrl: '/pages/admin-totp-setup.html'
            });
          }
        } else {
          // TOTP disabled
          const token = jwt.sign(
            { email, role: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
          );
          return res.json({ success: true, token, user: { email, role: 'admin' } });
        }
      } else {
        logger.error('❌ Password does not match hash');
        res.status(401).json({ error: 'Invalid credentials' });
      }
    } else {
      logger.error('❌ Email does not match');
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    logger.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 2FA verification validation
const validate2FAVerification = [
  body('twoFactorToken').notEmpty().withMessage('2FA token is required'),
  body('code').isLength({ min: 6, max: 6 }).withMessage('2FA code must be 6 digits'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Verify 2FA code and issue final admin JWT
app.post('/api/admin/2fa/verify', validate2FAVerification, async (req, res) => {
  try {
    const { twoFactorToken, code } = req.body || {};
    const record = twoFactorStore.get(twoFactorToken);
    if (!record) {
      return res.status(400).json({ error: 'Invalid or expired 2FA token' });
    }
    if (Date.now() > record.expiresAt) {
      twoFactorStore.delete(twoFactorToken);
      return res.status(400).json({ error: '2FA code expired' });
    }
    if (String(record.code) !== String(code)) {
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
    twoFactorStore.delete(twoFactorToken);

    const token = jwt.sign(
      { email: record.email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
    );
    res.json({ success: true, token, user: { email: record.email, role: 'admin' } });
  } catch (err) {
    logger.error('2FA verify error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// TOTP (Google Authenticator) Endpoints
// =============================================================================

// Persistent TOTP secret storage
const TOTP_SECRETS_FILE = path.join(__dirname, '.totp-secrets.json');

// Load TOTP secrets from file
function loadTotpSecrets() {
  try {
    if (fs.existsSync(TOTP_SECRETS_FILE)) {
      const data = fs.readFileSync(TOTP_SECRETS_FILE, 'utf8');
      return new Map(JSON.parse(data));
    }
  } catch (error) {
    logger.warn('Could not load TOTP secrets:', error.message);
  }
  return new Map();
}

// Save TOTP secrets to file
function saveTotpSecrets(secrets) {
  try {
    const data = JSON.stringify(Array.from(secrets.entries()));
    fs.writeFileSync(TOTP_SECRETS_FILE, data, 'utf8');
    logger.info('✅ TOTP secrets saved to file');
  } catch (error) {
    logger.error('❌ Could not save TOTP secrets:', error.message);
  }
}

const totpSecrets = loadTotpSecrets();

// Generate new TOTP secret
app.post('/api/admin/totp/generate', async (req, res) => {
  try {
    // Generate a new TOTP secret
    const secret = speakeasy.generateSecret({
      name: 'PLWGCREATIVEAPPAREL Admin',
      issuer: 'PLWGCREATIVEAPPAREL',
      length: 32
    });

    // Store the secret persistently
    totpSecrets.set('admin', secret.base32);
    saveTotpSecrets(totpSecrets);
    
    res.json({
      secret: secret.base32,
      secretKey: secret.base32,
      qrCode: secret.otpauth_url
    });
  } catch (error) {
    logger.error('TOTP generation error:', error);
    res.status(500).json({ error: 'Failed to generate TOTP secret' });
  }
});

// Verify TOTP code for setup
app.post('/api/admin/totp/verify', async (req, res) => {
  try {
    const { secret, code } = req.body;
    
    if (!secret || !code) {
      return res.status(400).json({ error: 'Secret and code required' });
    }

    // Verify the TOTP code
    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: code,
      window: 2 // Allow 2 time steps (60 seconds) for clock skew
    });

    if (verified) {
      // Mark TOTP as active and save persistently
      totpSecrets.set('admin', secret);
      saveTotpSecrets(totpSecrets);
      res.json({ valid: true, message: 'TOTP verified successfully' });
    } else {
      res.json({ valid: false, message: 'Invalid TOTP code' });
    }
  } catch (error) {
    logger.error('TOTP verification error:', error);
    res.status(500).json({ error: 'Failed to verify TOTP code' });
  }
});

// Verify TOTP code for login
app.post('/api/admin/totp/verify-login', async (req, res) => {
  try {
    const { email, password, code } = req.body;
    
    if (!email || !password || !code) {
      return res.status(400).json({ error: 'Email, password, and code required' });
    }

    // First verify admin credentials
    if (email.toLowerCase() !== process.env.ADMIN_EMAIL.toLowerCase()) {
      return res.status(401).json({ error: 'Invalid email' });
    }

    let isValidPassword = false;
    const activeHash = await getActiveAdminPasswordHash();
    if (activeHash) {
      isValidPassword = await bcrypt.compare(password, activeHash);
    } else if (process.env.ADMIN_PASSWORD) {
      isValidPassword = (password === process.env.ADMIN_PASSWORD);
    }

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Get stored TOTP secret
    const storedSecret = totpSecrets.get('admin');
    if (!storedSecret) {
      return res.status(400).json({ error: 'TOTP not configured. Please setup Google Authenticator first.' });
    }

    // Verify TOTP code
    const verified = speakeasy.totp.verify({
      secret: storedSecret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    if (verified) {
      // Generate JWT token
      const token = jwt.sign(
        { email, role: 'admin' },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '24h' }
      );
      
      res.json({ 
        success: true, 
        token, 
        user: { email, role: 'admin' } 
      });
    } else {
      res.status(401).json({ error: 'Invalid TOTP code' });
    }
  } catch (error) {
    logger.error('TOTP login verification error:', error);
    res.status(500).json({ error: 'Failed to verify TOTP code' });
  }
});

// Get TOTP status
app.get('/api/admin/totp/status', async (req, res) => {
  try {
    const secret = totpSecrets.get('admin');
    res.json({ 
      active: !!secret,
      configured: !!secret
    });
  } catch (error) {
    logger.error('TOTP status error:', error);
    res.status(500).json({ error: 'Failed to get TOTP status' });
  }
});

// Admin password reset validation
const validatePasswordResetRequest = [
  body('email').isEmail().withMessage('Please enter a valid email address'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

const validatePasswordReset = [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

const validatePasswordBootstrap = [
  body('newPassword').isLength({ min: 8 }).withMessage('New password must be at least 8 characters long'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];
// Request admin password reset (sends a token link/code to email)
app.post('/api/admin/password/request-reset', validatePasswordResetRequest, async (req, res) => {
  try {
    const { email } = req.body || {};
    const targetEmail = process.env.ADMIN_EMAIL;
    if (!email || !targetEmail || email.toLowerCase() !== targetEmail.toLowerCase()) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes
    passwordResetStore.set(token, { email: targetEmail, expiresAt });

    const toEmail = process.env.ADMIN_2FA_EMAIL || targetEmail || 'letsgetcreative@myyahoo.com';
    const resetHtml = `<p>You requested an admin password reset.</p>
      <p>Reset token:</p>
      <p style="font-size:14px;word-break:break-all;"><code>${token}</code></p>
      <p>This token expires in 30 minutes.</p>`;
    const sent = await sendEmail(toEmail, 'Admin Password Reset', resetHtml);
    if (!sent) {
      return res.status(500).json({ error: 'Failed to send reset email' });
    }
    res.json({ success: true });
  } catch (err) {
    logger.error('Password reset request error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Perform admin password reset using token
app.post('/api/admin/password/reset', validatePasswordReset, async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    const record = passwordResetStore.get(token);
    if (!record) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    if (Date.now() > record.expiresAt) {
      passwordResetStore.delete(token);
      return res.status(400).json({ error: 'Token expired' });
    }

    const newHash = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10));
    passwordResetStore.delete(token);

    // Persist new hash in DB admin_settings and update in-memory memo
    if (pool) {
      await pool.query(
        `INSERT INTO admin_settings(key, value, updated_at) VALUES('admin_password_hash', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [newHash]
      );
    }
    ADMIN_PASSWORD_HASH_MEMO = newHash;
    res.json({ success: true });
  } catch (err) {
    logger.error('Password reset error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// One-time bootstrap endpoint to set admin password without email (for emergencies)
// Requires ADMIN_BOOTSTRAP_TOKEN to be set in env and provided via header or body
app.post('/api/admin/password/bootstrap', validatePasswordBootstrap, async (req, res) => {
  try {
    const provided = req.headers['x-admin-bootstrap-token'] || (req.body && req.body.bootstrapToken);
    const expected = process.env.ADMIN_BOOTSTRAP_TOKEN;
    if (!expected) {
      return res.status(400).json({ error: 'Bootstrap not configured' });
    }
    if (!provided || String(provided) !== String(expected)) {
      return res.status(403).json({ error: 'Invalid bootstrap token' });
    }
    const { newPassword } = req.body || {};
    const newHash = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10));
    if (pool) {
      await pool.query(
        `INSERT INTO admin_settings(key, value, updated_at) VALUES('admin_password_hash', $1, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [newHash]
      );
    }
    ADMIN_PASSWORD_HASH_MEMO = newHash;
    res.json({ success: true });
  } catch (err) {
    logger.error('Bootstrap set password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// CUSTOMER PASSWORD RESET ENDPOINTS
// =============================================================================

// Customer password reset request validation
const validateCustomerPasswordResetRequest = [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required')
];

// Customer password reset validation
const validateCustomerPasswordReset = [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
];

// Request customer password reset (sends a token link to email)
app.post('/api/customer/password/request-reset', validateCustomerPasswordResetRequest, async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    if (!pool) {
      return res.status(500).json({ error: 'Database not available' });
    }

    // Check if customer exists
    const customerResult = await pool.query('SELECT id, name FROM customers WHERE email = $1', [email]);
    if (customerResult.rows.length === 0) {
      // Don't reveal if email exists or not for security
      return res.json({ success: true, message: 'If an account with that email exists, a reset link has been sent.' });
    }

    const customer = customerResult.rows[0];
    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes

    customerPasswordResetStore.set(token, { email, expiresAt });

    const resetUrl = `${process.env.BASE_URL || 'https://plwgscreativeapparel.com'}/pages/customer-password-reset.html?token=${token}`;
    const resetHtml = `
      <p>Hello ${customer.name || 'Customer'},</p>
      <p>You requested a password reset for your PLWGS Creative Apparel account.</p>
      <p>Click the link below to reset your password:</p>
      <p><a href="${resetUrl}" style="background:#ff8306;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block;">Reset Password</a></p>
      <p>If you didn't request this reset, please ignore this email.</p>
      <p>This link expires in 30 minutes.</p>
    `;

    const sent = await sendEmail(email, 'Password Reset - PLWGS Creative Apparel', resetHtml);
    if (!sent) {
      return res.status(500).json({ error: 'Failed to send reset email' });
    }

    res.json({ success: true, message: 'If an account with that email exists, a reset link has been sent.' });
  } catch (error) {
    logger.error('Customer password reset request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Perform customer password reset using token
app.post('/api/customer/password/reset', validateCustomerPasswordReset, async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};

    if (!token || !newPassword) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    const record = customerPasswordResetStore.get(token);
    if (!record) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    if (Date.now() > record.expiresAt) {
      customerPasswordResetStore.delete(token);
      return res.status(400).json({ error: 'Token expired' });
    }

    if (!pool) {
      return res.status(500).json({ error: 'Database not available' });
    }

    const newHash = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_SALT_ROUNDS || '12', 10));

    // Update customer password
    await pool.query('UPDATE customers SET password = $1, updated_at = NOW() WHERE email = $2', [newHash, record.email]);

    customerPasswordResetStore.delete(token);

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (error) {
    logger.error('Customer password reset error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify admin token
app.get('/api/admin/verify', authenticateToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// =============================================================================
// ORDER MANAGEMENT ENDPOINTS
// =============================================================================

// Get all orders
app.get('/api/orders', authenticateToken, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) {
    // Return mock data for development
    return res.json({ orders: [] });
  }

  try {
    const { status, limit = 50, offset = 0, q, date_from, date_to } = req.query;

    let query = `
      SELECT o.*, 
             c.name as customer_name, 
             c.email as customer_email,
             COUNT(oi.id) as item_count,
             json_agg(
               json_build_object(
                 'id', oi.id,
                 'product_name', oi.product_name,
                 'quantity', oi.quantity,
                 'size', oi.size,
                 'color', oi.color,
                 'unit_price', oi.unit_price,
                 'total_price', oi.total_price
               ) ORDER BY oi.id
             ) FILTER (WHERE oi.id IS NOT NULL) as order_items
      FROM orders o
      LEFT JOIN customers c ON o.customer_id = c.id
      LEFT JOIN order_items oi ON o.id = oi.order_id
    `;

    const params = [];
    const conditions = [];

    if (status) {
      conditions.push(`o.status = $${params.length + 1}`);
      params.push(status);
    }
    if (q) {
      conditions.push(`(o.order_number ILIKE $${params.length + 1} OR COALESCE(c.name,'') ILIKE $${params.length + 1})`);
      params.push(`%${q}%`);
    }
    if (date_from) {
      conditions.push(`o.created_at >= $${params.length + 1}::timestamp`);
      params.push(date_from);
    }
    if (date_to) {
      conditions.push(`o.created_at < ($${params.length + 1}::date + INTERVAL '1 day')`);
      params.push(date_to);
    }

    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }

    query += ` GROUP BY o.id, c.name, c.email, o.order_number, o.status, o.total_amount, o.created_at, o.customer_id, o.customer_email, o.customer_name, o.shipping_address, o.tracking_number, o.notes, o.updated_at, o.subtotal, o.shipping_amount, o.tax_amount, o.discount_amount, o.payment_method, o.payment_id, o.payment_status, o.payment_details ORDER BY o.created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(Math.min(parseInt(limit, 10) || 50, 200), parseInt(offset, 10) || 0);

    const result = await pool.query(query, params);
    console.log(`Orders API returning ${result.rows.length} orders`);
    console.log('Order statuses in result:', result.rows.map(o => ({ id: o.id, status: o.status, order_number: o.order_number })));
    res.json({ orders: result.rows });
  } catch (error) {
    logger.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Export orders as CSV for a given period (placed BEFORE :id route to avoid conflicts)
app.get('/api/orders/export', authenticateToken, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="orders_export.csv"`);
    return res.send('order_number,status,total_amount,created_at,customer_name\n');
  }
  try {
    const { period = '7d' } = req.query;
    let dateFilter = '';
    switch (period) {
      case '1d': dateFilter = "WHERE o.created_at >= CURRENT_DATE"; break;
      case '7d': dateFilter = "WHERE o.created_at >= CURRENT_DATE - INTERVAL '7 days'"; break;
      case '30d': dateFilter = "WHERE o.created_at >= CURRENT_DATE - INTERVAL '30 days'"; break;
      case '90d': dateFilter = "WHERE o.created_at >= CURRENT_DATE - INTERVAL '90 days'"; break;
      default: dateFilter = "WHERE o.created_at >= CURRENT_DATE - INTERVAL '7 days'"; break;
    }

    const result = await pool.query(`
      SELECT o.order_number, o.status, o.total_amount, o.created_at,
             COALESCE(c.name, '') AS customer_name
      FROM orders o
      LEFT JOIN customers c ON c.id = o.customer_id
      ${dateFilter}
      ORDER BY o.created_at DESC
    `);

    const rows = result.rows;
    const header = ['order_number','status','total_amount','created_at','customer_name'];
    const escape = (val) => {
      if (val === null || val === undefined) return '';
      const s = String(val).replace(/"/g, '""');
      return `"${s}"`;
    };
    const csv = [header.join(',')]
      .concat(rows.map(r => [r.order_number, r.status, r.total_amount, (r.created_at instanceof Date ? r.created_at.toISOString() : new Date(r.created_at).toISOString()), r.customer_name].map(escape).join(',')))
      .join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="orders_${period}.csv"`);
    res.send(csv);
  } catch (e) {
    logger.error('Error exporting orders:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get orders with custom input data
app.get('/api/orders/custom-input', async (req, res) => {
  try {
    if (!pool) {
      return res.json({ orders: [] });
    }
    // Check if the order_items table has the custom_input column
    const tableCheck = await pool.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'order_items' AND column_name = 'custom_input'
    `);
    
    if (tableCheck.rows.length === 0) {
      return res.json({ orders: [], message: 'custom_input column not found' });
    }
    
    // Main query to get orders with custom input
    const result = await pool.query(`
      SELECT 
        oi.id,
        oi.order_id,
        oi.product_name,
        oi.quantity,
        oi.unit_price,
        oi.total_price,
        oi.size,
        oi.color,
        oi.custom_input,
        o.order_number,
        o.customer_name,
        o.customer_email,
        o.total_amount,
        o.status as order_status,
        o.created_at
      FROM order_items oi
      JOIN orders o ON oi.order_id = o.id
      WHERE oi.custom_input IS NOT NULL 
        AND oi.custom_input != 'null' 
        AND oi.custom_input != '{}'
      ORDER BY o.id DESC
    `);
    
    res.json({ orders: result.rows });
  } catch (error) {
    logger.error('Error fetching orders with custom input:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Get order by ID
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const orderResult = await pool.query(`
      SELECT o.*, c.name as customer_name, c.email as customer_email
      FROM orders o
      LEFT JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [id]);
    
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    
    const itemsResult = await pool.query(`
      SELECT * FROM order_items WHERE order_id = $1
    `, [id]);
    
    res.json({
      order: orderResult.rows[0],
      items: itemsResult.rows
    });
  } catch (error) {
    logger.error('Error fetching order:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Order status update validation
const validateOrderStatusUpdate = [
  body('status').isIn(['pending', 'processing', 'shipped', 'completed', 'delivered', 'cancelled']).withMessage('Invalid order status'),
  body('tracking_number').optional().isString().trim().withMessage('Tracking number must be a string'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Update order status
app.patch('/api/orders/:id/status', authenticateToken, validateOrderStatusUpdate, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, tracking_number } = req.body;
    
    console.log(`🔧 UPDATING ORDER ${id} TO STATUS: ${status}`);
    console.log(`🔧 Request body:`, req.body);
    
    const result = await pool.query(`
      UPDATE orders 
      SET status = $1, tracking_number = $2, updated_at = CURRENT_TIMESTAMP
      WHERE id = $3 RETURNING *
    `, [status, tracking_number, id]);
    
    console.log(`🔧 UPDATE RESULT:`, result.rows[0]);
    console.log(`🔧 ROWS AFFECTED:`, result.rowCount);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const updated = result.rows[0];

    // Seed a notification on status change (best-effort)
    try {
      await pool.query(`
        INSERT INTO notifications (type, title, body, link, is_read)
        VALUES ($1, $2, $3, $4, false)
      `, [
        'order',
        `Order ${updated.order_number} updated`,
        `Status changed to ${status.toUpperCase()}`,
        `order:${updated.id}`
      ]);
    } catch (e) {
      logger.warn('Notification insert failed (non-fatal):', e.message);
    }

    res.json({ order: updated });
  } catch (error) {
    logger.error('Error updating order:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Order validation
const validateOrder = [
  body('customer_email').isEmail().withMessage('Please enter a valid customer email'),
  body('customer_name').notEmpty().trim().withMessage('Customer name is required'),
  body('items').isArray({ min: 1 }).withMessage('Order must contain at least one item'),
  body('total_amount').isFloat({ min: 0 }).withMessage('Total amount must be a positive number'),
  body('shipping_address').notEmpty().trim().withMessage('Shipping address is required'),
  body('items.*.product_id').isInt({ min: 1 }).withMessage('Product ID must be a positive integer'),
  body('items.*.product_name').notEmpty().trim().withMessage('Product name is required'),
  body('items.*.quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  body('items.*.unit_price').isFloat({ min: 0 }).withMessage('Unit price must be a positive number'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Create new order
app.post('/api/orders', validateOrder, async (req, res) => {
  try {
    const { customer_email, customer_name, items, total_amount, shipping_address } = req.body;
    
    // Generate order number
    const orderNumber = 'ORD-' + Date.now();
    
    // Create customer if doesn't exist
    let customerResult = await pool.query(
      'SELECT id FROM customers WHERE email = $1',
      [customer_email]
    );
    
    let customerId = null;
    if (customerResult.rows.length === 0) {
      const newCustomer = await pool.query(
        'INSERT INTO customers (email, name) VALUES ($1, $2) RETURNING id',
        [customer_email, customer_name]
      );
      customerId = newCustomer.rows[0].id;
    } else {
      customerId = customerResult.rows[0].id;
    }
    
    // Create order
    const orderResult = await pool.query(`
            INSERT INTO orders (order_number, customer_id, customer_email, customer_name, total_amount, shipping_address, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'pending') RETURNING *
    `, [orderNumber, customerId, customer_email, customer_name, total_amount, shipping_address]);
    
    const order = orderResult.rows[0];
    
    // Create order items
    let hasCustomInput = false;
    for (const item of items) {
      await pool.query(`
        INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price, size, color, image_url, custom_input)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [order.id, item.product_id, item.product_name, item.quantity, item.unit_price, item.total_price, item.size, item.color, item.image_url, item.custom_input]);

      // Check if this item has custom input
      if (item.custom_input && item.custom_input !== '{}' && item.custom_input !== 'null') {
        hasCustomInput = true;
      }
    }

    // Send email notification to admin if order has custom input
    if (hasCustomInput) {
      try {
        const adminEmail = process.env.ADMIN_EMAIL || 'lori@plwgcreativeapparel.com';

        // Build custom input summary
        let customInputSummary = '';
        items.forEach((item, index) => {
          if (item.custom_input && item.custom_input !== '{}' && item.custom_input !== 'null') {
            const inputData = typeof item.custom_input === 'string' ? JSON.parse(item.custom_input) : item.custom_input;

            customInputSummary += `\n\n📦 ITEM ${index + 1}: ${item.product_name}\n`;
            customInputSummary += `   Size: ${item.size}, Color: ${item.color}, Quantity: ${item.quantity}\n`;

            // Standard custom inputs
            const standardFields = Object.keys(inputData).filter(key =>
              (key.includes('birthday_') || key.includes('lyrics_')) &&
              !key.includes('custom_question')
            );

            if (standardFields.length > 0) {
              customInputSummary += `   Standard Details:\n`;
              standardFields.forEach(key => {
                const displayKey = key.replace('birthday_', '').replace('lyrics_', '').replace(/_/g, ' ');
                customInputSummary += `     ${displayKey}: ${inputData[key]}\n`;
              });
            }

            // Custom questions
            const customQuestions = Object.keys(inputData).filter(key => key.includes('custom_question'));
            if (customQuestions.length > 0) {
              customInputSummary += `   🎯 CUSTOM QUESTIONS:\n`;
              customQuestions.forEach(key => {
                const questionType = key.includes('birthday') ? 'Birthday Question' : 'Lyrics Question';
                customInputSummary += `     ${questionType}: "${inputData[key]}"\n`;
              });
            }
          }
        });

        const customOrderHTML = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h1 style="color: #00bcd4; border-bottom: 2px solid #00bcd4; padding-bottom: 10px;">
                🎨 New Order with Custom Input!
              </h1>

              <div style="background: #f5f5f5; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h2 style="margin-top: 0; color: #333;">Order Details:</h2>
                <p><strong>Order #:</strong> ${orderNumber}</p>
                <p><strong>Customer:</strong> ${customer_name}</p>
                <p><strong>Email:</strong> ${customer_email}</p>
                <p><strong>Total:</strong> $${total_amount}</p>
                <p><strong>Date:</strong> ${new Date().toLocaleString()}</p>
              </div>

              <div style="background: #fff3cd; border: 2px solid #ffc107; padding: 20px; border-radius: 8px; margin: 20px 0;">
                <h2 style="margin-top: 0; color: #856404;">🎯 CUSTOM INPUT DETAILS:</h2>
                <pre style="white-space: pre-wrap; font-family: monospace; background: white; padding: 15px; border-radius: 4px; border: 1px solid #dee2e6;">${customInputSummary}</pre>
              </div>

              <div style="background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 4px; margin: 20px 0;">
                <p style="margin: 0;"><strong>📧 Action Required:</strong> This order contains custom personalization requests that need your attention.</p>
              </div>

              <div style="text-align: center; margin: 30px 0;">
                <a href="${process.env.ADMIN_URL || 'http://localhost:3000'}/pages/admin.html"
                   style="background: #00bcd4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">
                  View in Admin Dashboard
                </a>
              </div>

              <hr style="border: none; border-top: 1px solid #dee2e6; margin: 30px 0;">

              <p style="color: #6c757d; font-size: 12px;">
                This is an automated notification for orders containing custom input.
                Please log into your admin dashboard to process this order.
              </p>
            </div>
        `;

        await sendResendEmail(
          adminEmail,
          `🚨 NEW ORDER WITH CUSTOM INPUT - ${orderNumber}`,
          customOrderHTML
        );
        logger.info(`✅ Admin notification sent for custom order ${orderNumber}`);

      } catch (emailError) {
        logger.error('❌ Failed to send admin notification email:', emailError);
        // Don't fail the order creation if email fails
      }
    }

    res.json({ order });
  } catch (error) {
    logger.error('Error creating order:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// PRODUCT MANAGEMENT ENDPOINTS
// =============================================================================

// Get all products
app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM products ORDER BY created_at DESC
    `);
    res.json({ products: result.rows });
  } catch (error) {
    logger.error('Error fetching products:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Public product validation
const validatePublicProduct = [
  body('name').notEmpty().trim().withMessage('Product name is required'),
  body('description').optional().isString().withMessage('Description must be a string'),
  body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  body('image_url').optional().isURL().withMessage('Image URL must be a valid URL'),
  body('category').notEmpty().trim().withMessage('Category is required'),
  body('stock_quantity').optional().isInt({ min: 0 }).withMessage('Stock quantity must be a non-negative integer'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Create new product
app.post('/api/products', authenticateToken, validatePublicProduct, async (req, res) => {
  try {
    const { name, description, price, image_url, category, stock_quantity } = req.body;
    
    const result = await pool.query(`
      INSERT INTO products (name, description, price, image_url, category, stock_quantity)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
    `, [name, description, price, image_url, category, stock_quantity]);
    
    res.json({ product: result.rows[0] });
  } catch (error) {
    logger.error('Error creating product:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update product
app.put('/api/products/:id', authenticateToken, validatePublicProduct, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, image_url, category, stock_quantity, is_active } = req.body;
    
    const result = await pool.query(`
      UPDATE products 
      SET name = $1, description = $2, price = $3, image_url = $4, category = $5, stock_quantity = $6, is_active = $7, updated_at = CURRENT_TIMESTAMP
      WHERE id = $8 RETURNING *
    `, [name, description, price, image_url, category, stock_quantity, is_active, id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json({ product: result.rows[0] });
  } catch (error) {
    logger.error('Error updating product:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete product
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('DELETE FROM products WHERE id = $1 RETURNING *', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    logger.error('Error deleting product:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// CUSTOMER MANAGEMENT ENDPOINTS
// =============================================================================

// Get all customers (with optional search/pagination)
app.get('/api/customers', authenticateToken, async (req, res) => {
  try {
    const { q, limit = 30, offset = 0 } = req.query;
    const params = [];
    let where = '';
    if (q) {
      where = `WHERE (c.email ILIKE $1 OR COALESCE(c.name,'') ILIKE $1)`;
      params.push(`%${q}%`);
    }

    const result = await pool.query(`
      SELECT c.*, 
             COUNT(o.id) as total_orders,
             COALESCE(SUM(o.total_amount),0) as total_spent
      FROM customers c
      LEFT JOIN orders o ON c.id = o.customer_id
      ${where}
      GROUP BY c.id
      ORDER BY c.created_at DESC
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}
    `, [...params, Math.min(parseInt(limit, 10) || 30, 200), parseInt(offset, 10) || 0]);

    res.json({ customers: result.rows });
  } catch (error) {
    logger.error('Error fetching customers:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get customer by ID
app.get('/api/customers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const customerResult = await pool.query('SELECT * FROM customers WHERE id = $1', [id]);
    
    if (customerResult.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    const ordersResult = await pool.query(`
      SELECT * FROM orders WHERE customer_id = $1 ORDER BY created_at DESC
    `, [id]);
    
    res.json({
      customer: customerResult.rows[0],
      orders: ordersResult.rows
    });
  } catch (error) {
    logger.error('Error fetching customer:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// CUSTOM REQUESTS ENDPOINTS
// =============================================================================

// Test database connection
app.get('/api/test-db', async (req, res) => {
  try {
    logger.info('🧪 Testing database connection...');
    logger.info('🔍 Pool object:', pool);
    
    if (!pool) {
      logger.error('❌ Database pool is null/undefined');
      return res.status(500).json({ error: 'Database pool not available' });
    }
    
    // Test basic connection
    const testResult = await pool.query('SELECT NOW() as current_time');
    logger.info('🔍 Basic query test:', testResult.rows[0]);
    
    // Test if order_items table exists
    const tableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name = 'order_items'
      ) as table_exists
    `);
    
    logger.info('🔍 order_items table exists:', tableExists.rows[0]);
    
    res.json({ 
      message: 'Database test successful',
      pool_available: !!pool,
      basic_query: testResult.rows[0],
      order_items_exists: tableExists.rows[0].table_exists
    });
  } catch (error) {
    logger.error('❌ Database test error:', error);
    res.status(500).json({ error: 'Database test failed', details: error.message });
  }
});



// Get all custom requests
app.get('/api/custom-requests', authenticateToken, async (req, res) => {
  try {
    const { status, priority } = req.query;
    
    let query = 'SELECT * FROM custom_requests';
    const params = [];
    const conditions = [];
    
    if (status) {
      conditions.push(`status = $${params.length + 1}`);
      params.push(status);
    }
    
    if (priority) {
      conditions.push(`priority = $${params.length + 1}`);
      params.push(priority);
    }
    
    if (conditions.length > 0) {
      query += ` WHERE ${conditions.join(' AND ')}`;
    }
    
    query += ' ORDER BY created_at DESC';
    
    if (!pool) {
      return res.json({ requests: [] });
    }
    const result = await pool.query(query, params);
    res.json({ requests: result.rows });
  } catch (error) {
    logger.error('Error fetching custom requests:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get single custom request by ID
app.get('/api/custom-requests/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(`
      SELECT * FROM custom_requests WHERE id = $1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    res.json({ request: result.rows[0] });
  } catch (error) {
    logger.error('Error fetching custom request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update custom request status
app.patch('/api/custom-requests/:id/status', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;
    
    const result = await pool.query(`
      UPDATE custom_requests 
      SET status = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 RETURNING *
    `, [status, id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    res.json({ request: result.rows[0] });
  } catch (error) {
    logger.error('Error updating custom request:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Custom request validation middleware
const validateCustomRequest = [
  body('fullName').notEmpty().trim().withMessage('Full name is required'),
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('phone').optional().isMobilePhone().withMessage('Please enter a valid phone number'),
  body('concept').notEmpty().trim().withMessage('Concept description is required'),
  body('productType').notEmpty().trim().withMessage('Product type is required'),
  body('quantity').isIn(['1', '2-5', '6-10', '11-25', '25+']).withMessage('Please select a valid quantity range'),
  body('budget').isIn(['50-100', '100-250', '250-500', '500-1000', '1000+']).withMessage('Please select a valid budget range'),
  body('timeline').optional().isIn(['standard', 'rush', 'express']).withMessage('Timeline must be standard, rush, or express'),
  body('styles').optional().isArray().withMessage('Styles must be an array'),
  body('sizes').optional().isArray().withMessage('Sizes must be an array'),
  body('colors').optional().isString().withMessage('Colors must be a string'),
  body('notes').optional().isString().withMessage('Notes must be a string'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Create new custom request
app.post('/api/custom-requests', validateCustomRequest, async (req, res) => {
  try {
    logger.info('📝 Custom request received:', req.body);
    
    const {
      fullName,
      email,
      phone,
      timeline,
      concept,
      styles,
      productType,
      quantity,
      sizes,
      colors,
      budget,
      notes,
      referenceImages
    } = req.body;

    // Process reference images if provided
    let processedReferenceImages = null;
    if (referenceImages && referenceImages.length > 0) {
      try {
        logger.info('🖼️ Processing reference images...');
        processedReferenceImages = [];
        
        for (const image of referenceImages) {
          if (image.data && image.data.startsWith('data:image/')) {
            // Upload to Cloudinary
            const cloudinaryUrl = await uploadImageToCloudinary(image.data, 'custom-requests');
            processedReferenceImages.push({
              originalName: image.name,
              cloudinaryUrl: cloudinaryUrl,
              thumbnailUrl: cloudinaryUrl.replace('/upload/', '/upload/w_300,h_200,c_fill,g_auto/'),
              size: image.size,
              type: image.type
            });
          }
        }
        logger.info(`✅ Processed ${processedReferenceImages.length} reference images`);
      } catch (imageError) {
        logger.error('❌ Error processing reference images:', imageError);
        // Don't fail the request if image processing fails
        processedReferenceImages = null;
      }
    }

    logger.info('✅ Required fields validated');

    // Check if database is available
    const dbCheck = checkDatabase();
    logger.info('��️ Database check:', dbCheck);
    
    if (!dbCheck.available) {
      logger.warn('⚠️ Database not available, using mock request');
      
      // Create mock custom request object for email - using existing table structure exactly
      const mockCustomRequest = {
        id: Date.now(),
        customer_name: fullName,
        customer_email: email,
        customer_phone: phone || null,
        request_type: productType,
        description: concept,
        quantity: parseInt(quantity.split('-')[0]) || 1,
        estimated_budget: parseFloat(budget.split('-')[0]) || 50,
        status: 'pending',
        timeline: timeline,
        style_preferences: styles ? JSON.stringify(styles) : null,
        size_requirements: sizes ? JSON.stringify(sizes) : null,
        color_preferences: colors || null,
        additional_notes: notes || null,
        reference_images: processedReferenceImages ? JSON.stringify(processedReferenceImages) : null,
        concept_description: concept,
        created_at: new Date()
      };

      logger.info('📧 Sending email for mock request...');

      // Send email notifications
      try {
        // Send admin notification
        await sendCustomRequestEmail(mockCustomRequest);
        logger.info('✅ Admin notification email sent successfully');
        
        // Send customer confirmation
        await sendCustomerConfirmationEmail(mockCustomRequest);
        logger.info('✅ Customer confirmation email sent successfully');
      } catch (emailError) {
        logger.error('❌ Error sending emails:', emailError);
        // Don't fail the request if email fails
      }

      logger.info('✅ Returning mock response');
      return res.status(201).json({ 
        success: true, 
        message: 'Custom request submitted successfully! We\'ll review your submission and get back to you within 24 hours.',
        request: mockCustomRequest 
      });
    }

    logger.info('🗄️ Database available, inserting into database...');

    // Insert into database - using existing table structure exactly
    const result = await pool.query(`
      INSERT INTO custom_requests (
        customer_name, customer_email, customer_phone, request_type, description, 
        quantity, estimated_budget, status, timeline, style_preferences, 
        size_requirements, color_preferences, additional_notes, reference_images, 
        concept_description, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
      RETURNING *
    `, [
      fullName, email, phone || null, productType, concept,
      // Convert quantity string to integer (take first number from range like "2-5" -> 2)
      parseInt(quantity.split('-')[0]) || 1,
      // Convert budget string to numeric (take first number from range like "50-100" -> 50)
      parseFloat(budget.split('-')[0]) || 50,
      'pending', timeline, 
      styles ? JSON.stringify(styles) : null, 
      sizes ? JSON.stringify(sizes) : null, 
      colors || null, notes || null, 
      processedReferenceImages ? JSON.stringify(processedReferenceImages) : null,
      concept, new Date()
    ]);

    const customRequest = result.rows[0];
    logger.info('✅ Database insert successful');

    // Send email notifications
    try {
      // Send admin notification
      await sendCustomRequestEmail(customRequest);
      logger.info('✅ Admin notification email sent successfully');
      
      // Send customer confirmation
      await sendCustomerConfirmationEmail(customRequest);
      logger.info('✅ Customer confirmation email sent successfully');
    } catch (emailError) {
      logger.error('❌ Error sending emails:', emailError);
      // Don't fail the request if email fails
    }

    logger.info('✅ Returning success response');
    res.status(201).json({ 
      success: true, 
      message: 'Custom request submitted successfully! We\'ll review your submission and get back to you within 24 hours.',
      request: customRequest 
    });

  } catch (error) {
    logger.error('❌ Error creating custom request:', error);
    logger.error('❌ Error stack:', error.stack);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// CUSTOM REQUESTS CUSTOMER ENDPOINTS
// =============================================================================

// Get custom requests for a customer by email (no auth required)
app.get('/api/custom-requests/customer/:email', async (req, res) => {
  try {
    const { email } = req.params;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const result = await pool.query(`
      SELECT 
        id, customer_name, timeline, concept_description, 
        style_preferences, request_type, quantity, size_requirements, 
        color_preferences, estimated_budget, additional_notes, 
        status, created_at, updated_at
      FROM custom_requests 
      WHERE customer_email = $1 
      ORDER BY created_at DESC
    `, [email]);
    
    res.json({ 
      requests: result.rows,
      count: result.rows.length 
    });
  } catch (error) {
    logger.error('Error fetching customer custom requests:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// ANALYTICS ENDPOINTS
// =============================================================================

// Get dashboard analytics
app.get('/api/analytics/dashboard', authenticateToken, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) {
    // Return mock data for development
    return res.json({
      sales: { total_sales: 0, total_orders: 0 },
      topProducts: [],
      dailySales: [],
      lowStock: []
    });
  }

  try {
    const { period = '7d' } = req.query;
    
    let dateFilter = '';
    switch (period) {
      case '1d':
        dateFilter = "WHERE created_at >= CURRENT_DATE";
        break;
      case '7d':
        dateFilter = "WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'";
        break;
      case '30d':
        dateFilter = "WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'";
        break;
      case '90d':
        dateFilter = "WHERE created_at >= CURRENT_DATE - INTERVAL '90 days'";
        break;
    }
    
    // Total sales
    const salesResult = await pool.query(`
      SELECT COALESCE(SUM(total_amount), 0) as total_sales,
             COUNT(*) as total_orders
      FROM orders ${dateFilter}
    `);
    
    // Top products - always query regardless of date filter
    const topProductsResult = await pool.query(`
      SELECT oi.product_name,
             SUM(oi.quantity) as total_sold,
             SUM(oi.total_price) as total_revenue,
             p.image_url,
             p.id as product_id
      FROM order_items oi
      JOIN orders o ON oi.order_id = o.id
      LEFT JOIN products p ON p.name = oi.product_name
      ${dateFilter ? dateFilter.replace('WHERE', 'WHERE o.') : ''}
      GROUP BY oi.product_name, p.image_url, p.id
      ORDER BY total_revenue DESC
      LIMIT 5
    `);
    
    // Sales by day
    const dailySalesResult = await pool.query(`
      SELECT DATE(created_at) as date,
             SUM(total_amount) as daily_sales,
             COUNT(*) as daily_orders
      FROM orders ${dateFilter}
      GROUP BY DATE(created_at)
      ORDER BY date DESC
      LIMIT 30
    `);
    
    // Low stock products
    const lowStockResult = await pool.query(`
      SELECT id AS product_id, name, stock_quantity, low_stock_threshold
      FROM products
      WHERE stock_quantity <= low_stock_threshold AND is_active = true
      ORDER BY stock_quantity ASC
    `);

    // Custom requests count (period-aware) - includes both custom_requests and orders with custom input
    let customRequestsCountResult;
    if (dateFilter) {
      // If there's a date filter, apply it to both tables
      customRequestsCountResult = await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM (
          SELECT id FROM custom_requests ${dateFilter}
          UNION ALL
          SELECT o.id 
          FROM orders o
          JOIN order_items oi ON o.id = oi.order_id
          WHERE oi.custom_input IS NOT NULL 
          AND oi.custom_input != '{}'
          AND o.status != 'completed'
          ${dateFilter.replace('WHERE', 'AND o.')}
        ) AS all_custom_requests
      `);
    } else {
      // If no date filter, just count all pending custom requests
      customRequestsCountResult = await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM (
          SELECT id FROM custom_requests
          UNION ALL
          SELECT o.id 
          FROM orders o
          JOIN order_items oi ON o.id = oi.order_id
          WHERE oi.custom_input IS NOT NULL 
          AND oi.custom_input != '{}'
          AND o.status != 'completed'
        ) AS all_custom_requests
      `);
    }
    
    res.json({
      sales: salesResult.rows[0],
      topProducts: topProductsResult.rows,
      dailySales: dailySalesResult.rows,
      lowStock: lowStockResult.rows,
      customRequestsCount: customRequestsCountResult.rows[0]?.count || 0
    });
  } catch (error) {
    logger.error('Error fetching analytics:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get sales time series for chart
app.get('/api/analytics/sales-series', authenticateToken, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) {
    return res.json({ series: [] });
  }

  try {
    const { period = '7d' } = req.query;
    let numDays = 7;
    switch (period) {
      case '1d': numDays = 1; break;
      case '7d': numDays = 7; break;
      case '30d': numDays = 30; break;
      case '90d': numDays = 90; break;
      default: numDays = 7; break;
    }

    // Build a continuous date series including zero-sale days
    const seriesResult = await pool.query(`
      WITH dates AS (
        SELECT generate_series(CURRENT_DATE - INTERVAL '${numDays - 1} days', CURRENT_DATE, INTERVAL '1 day')::date AS date
      )
      SELECT d.date,
             COALESCE(SUM(o.total_amount), 0) AS total
      FROM dates d
      LEFT JOIN orders o ON DATE(o.created_at) = d.date
      GROUP BY d.date
      ORDER BY d.date ASC
    `);

    res.json({ series: seriesResult.rows });
  } catch (e) {
    logger.error('Error fetching sales series:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// INVENTORY MANAGEMENT ENDPOINTS
// =============================================================================

// Get inventory status
app.get('/api/inventory', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, stock_quantity, low_stock_threshold, 
             CASE 
               WHEN stock_quantity = 0 THEN 'out_of_stock'
               WHEN stock_quantity <= low_stock_threshold THEN 'low_stock'
               ELSE 'in_stock'
             END as status
      FROM products
      WHERE is_active = true
      ORDER BY stock_quantity ASC
    `);
    
    res.json({ inventory: result.rows });
  } catch (error) {
    logger.error('Error fetching inventory:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// ORDERS HELPERS
// =============================================================================

// Process all orders validation
const validateProcessAllOrders = [
  body('status').optional().isIn(['processing', 'shipped']).withMessage('Status must be processing or shipped'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Process all pending orders into processing
app.post('/api/orders/process-all', authenticateToken, validateProcessAllOrders, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) {
    return res.json({ moved: 0 });
  }
  try {
    const result = await pool.query(`
      UPDATE orders
      SET status = 'processing', updated_at = CURRENT_TIMESTAMP
      WHERE status = 'pending'
      RETURNING id
    `);
    res.json({ moved: result.rowCount });
  } catch (e) {
    logger.error('Error processing all orders:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset all orders to pending status for testing
app.post('/api/orders/reset-to-pending', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('UPDATE orders SET status = $1 WHERE status = $2', ['pending', 'completed']);
    res.json({ success: true, message: `Updated ${result.rowCount} orders to pending status` });
  } catch (error) {
    logger.error('❌ Error updating orders:', error.message);
    res.status(500).json({ error: 'Failed to update orders' });
  }
});

// (duplicate '/api/orders/export' removed; export route is defined earlier, before '/api/orders/:id')

// =============================================================================
// ADMIN ACTIVITY FEED (READ-ONLY)
// =============================================================================

app.get('/api/admin/activity', authenticateToken, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) return res.json({ activity: [] });
  try {
    const { limit = 20 } = req.query;

    const orders = await pool.query(`
      SELECT 'order' AS type, order_number AS title, 
             CONCAT('Total $', total_amount) AS subtitle,
             total_amount AS amount, created_at, 
             CONCAT('order:', id) AS link
      FROM orders
      ORDER BY created_at DESC
      LIMIT 20
    `);

    const products = await pool.query(`
      SELECT 'product' AS type, name AS title,
             'New product uploaded' AS subtitle,
             price AS amount, created_at,
             CONCAT('product:', id) AS link
      FROM products
      ORDER BY created_at DESC
      LIMIT 20
    `);

    const lowStock = await pool.query(`
      SELECT 'inventory' AS type, name AS title,
             CONCAT('Low stock: ', stock_quantity, ' remaining') AS subtitle,
             NULL::numeric AS amount, NOW() AS created_at,
             CONCAT('product:', id) AS link
      FROM products
      WHERE stock_quantity <= low_stock_threshold AND is_active = true
      ORDER BY stock_quantity ASC
      LIMIT 20
    `);

    const customReq = await pool.query(`
      SELECT 'custom_request' AS type, customer_name AS title,
             'Custom order request' AS subtitle,
             NULL::numeric AS amount, created_at,
             CONCAT('custom_request:', id) AS link
      FROM custom_requests
      ORDER BY created_at DESC
      LIMIT 20
    `);

    const combined = [...orders.rows, ...products.rows, ...lowStock.rows, ...customReq.rows]
      .sort((a,b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, Math.min(parseInt(limit, 10) || 20, 100));

    res.json({ activity: combined });
  } catch (e) {
    logger.error('Error fetching admin activity:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// NOTIFICATIONS (READ-ONLY + MARK READ)
// =============================================================================

app.get('/api/admin/notifications', authenticateToken, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) return res.json({ notifications: [] });
  try {
    const { unread } = req.query;
    const where = unread === 'true' ? 'WHERE is_read = false' : '';
    const result = await pool.query(`
      SELECT id, type, title, body, link, is_read, created_at
      FROM notifications
      ${where}
      ORDER BY created_at DESC
      LIMIT 50
    `);
    res.json({ notifications: result.rows });
  } catch (e) {
    // If table does not exist yet, return empty array safely
    logger.warn('Notifications fetch fallback:', e.message);
    res.json({ notifications: [] });
  }
});

app.patch('/api/admin/notifications/read', authenticateToken, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) return res.json({ updated: 0 });
  try {
    const result = await pool.query(`
      UPDATE notifications SET is_read = true WHERE is_read = false RETURNING id
    `);
    res.json({ updated: result.rowCount });
  } catch (e) {
    logger.warn('Notifications mark-read fallback:', e.message);
    res.json({ updated: 0 });
  }
});

// Update product stock
app.patch('/api/products/:id/stock', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { stock_quantity } = req.body;
    
    const result = await pool.query(`
      UPDATE products 
      SET stock_quantity = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 RETURNING *
    `, [stock_quantity, id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json({ product: result.rows[0] });
  } catch (error) {
    logger.error('Error updating stock:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================================================
// CONTACT FORM ENDPOINTS
// =============================================================================

// Contact form validation
const validateContactForm = [
  body('firstName').notEmpty().trim().withMessage('First name is required'),
  body('lastName').notEmpty().trim().withMessage('Last name is required'),
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('phone').optional().isMobilePhone().withMessage('Please enter a valid phone number'),
  body('subject').notEmpty().withMessage('Subject is required'),
  body('message').isLength({ min: 10 }).withMessage('Message must be at least 10 characters long'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Handle contact form submission
app.post('/api/contact', validateContactForm, async (req, res) => {
  try {
    const { firstName, lastName, email, phone, subject, message, newsletter } = req.body;
    
    // Store contact submission in database (optional)
    const dbCheck = checkDatabase();
    let contactId = null;
    
    if (dbCheck.available) {
      try {
        // Create contact_submissions table if it doesn't exist
        await pool.query(`
          CREATE TABLE IF NOT EXISTS contact_submissions (
            id SERIAL PRIMARY KEY,
            first_name VARCHAR(100),
            last_name VARCHAR(100),
            email VARCHAR(255),
            phone VARCHAR(50),
            subject VARCHAR(255),
            message TEXT,
            newsletter_opt_in BOOLEAN DEFAULT false,
            status VARCHAR(50) DEFAULT 'new',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        `);
        
        // Insert contact submission
        const result = await pool.query(`
          INSERT INTO contact_submissions (first_name, last_name, email, phone, subject, message, newsletter_opt_in)
          VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
        `, [firstName, lastName, email, phone || null, subject, message, newsletter === 'on']);
        
        contactId = result.rows[0].id;
        logger.info(`📝 Contact submission stored with ID: ${contactId}`);
      } catch (dbError) {
        logger.error('Database error storing contact submission:', dbError);
        // Continue without storing in database
      }
    }
    
    // Send email notifications
    await sendContactFormEmails({
      id: contactId,
      firstName,
      lastName,
      email,
      phone,
      subject,
      message,
      newsletter
    });
    
    // If newsletter subscription was requested, add to newsletter
    if (newsletter === 'on') {
      try {
        if (dbCheck.available) {
          // Check if already subscribed
          const existing = await pool.query('SELECT * FROM subscribers WHERE email = $1', [email]);
          
          if (existing.rows.length === 0) {
            // Add to newsletter
            await pool.query(
              'INSERT INTO subscribers (email, name, welcome_email_sent) VALUES ($1, $2, $3)',
              [email, `${firstName} ${lastName}`, true] // Mark as sent since we'll send it with contact confirmation
            );
            logger.info(`📧 Added ${email} to newsletter via contact form`);
          }
        }
      } catch (newsletterError) {
        logger.error('Error adding to newsletter:', newsletterError);
        // Don't fail the contact form if newsletter signup fails
      }
    }
    
    res.json({ 
      success: true, 
      message: 'Thank you for your message! We\'ll get back to you within 24 hours.',
      contactId: contactId 
    });

  } catch (error) {
    logger.error('Error processing contact form:', error);
    res.status(500).json({ error: 'Internal server error. Please try again.' });
  }
});

// Send contact form emails
async function sendContactFormEmails(contactData) {
  try {
    // Send confirmation email to customer
    await sendCustomerContactConfirmation(contactData);
    
    // Send notification email to admin
    await sendAdminContactNotification(contactData);
    
    logger.info(`✅ Contact form emails sent for ${contactData.email}`);
  } catch (error) {
    logger.error('❌ Error sending contact form emails:', error);
    throw error;
  }
}

// Send confirmation email to customer
async function sendCustomerContactConfirmation(contactData) {
  const customerEmailHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Thank You for Contacting PLWG'S Creative Apparel</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                overflow: hidden;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 28px;
                font-weight: 700;
            }
            .content {
                padding: 40px 30px;
            }
            .message-details {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                border-left: 4px solid #ff8306;
            }
            .footer {
                background: #f8f9fa;
                padding: 30px;
                text-align: center;
                color: #666;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>✅ Message Received!</h1>
                <p>Thank you for contacting PLWG'S Creative Apparel</p>
            </div>
            
            <div class="content">
                <p>Hi ${contactData.firstName},</p>
                
                <p>Thank you for reaching out to us! We've received your message and will get back to you within 24 hours during business days.</p>
                
                <div class="message-details">
                    <h3>Your Message Details:</h3>
                    <p><strong>Subject:</strong> ${contactData.subject}</p>
                    <p><strong>Message:</strong></p>
                    <p style="font-style: italic;">"${contactData.message}"</p>
                </div>
                
                <p><strong>What happens next?</strong></p>
                <ul>
                    <li>Our team will review your message</li>
                    <li>We'll respond within 24 hours (business days)</li>
                    <li>For urgent matters, you can also email us directly at admin@plwgscreativeapparel.com</li>
                </ul>
                
                <p>In the meantime, feel free to browse our latest designs and custom apparel options on our website!</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="https://plwgscreativeapparel.com/pages/shop.html" 
                       style="display: inline-block; background: linear-gradient(135deg, #ff8306 0%, #ffa726 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; font-weight: bold;">
                        Browse Our Shop
                    </a>
                </div>
            </div>
            
            <div class="footer">
                <p><strong>PLWG'S Creative Apparel</strong></p>
                <p>Custom DTG Printing & Unique Designs</p>
                <p>Questions? Contact us at <a href="mailto:admin@plwgscreativeapparel.com">admin@plwgscreativeapparel.com</a></p>
            </div>
        </div>
    </body>
    </html>
  `;

  await sendResendEmail(
    contactData.email,
    '✅ Thank You for Contacting PLWG\'S Creative Apparel',
    customerEmailHTML
  );
  logger.info(`✅ Customer contact confirmation sent to ${contactData.email}`);
}

// Send notification email to admin
async function sendAdminContactNotification(contactData) {
  const adminEmailHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Contact Form Submission</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
                background: #f4f4f4;
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: white;
                border-radius: 10px;
                overflow: hidden;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            }
            .header {
                background: linear-gradient(135deg, #ff8306 0%, #ffa726 100%);
                color: white;
                padding: 30px;
                text-align: center;
            }
            .content {
                padding: 30px;
            }
            .contact-details {
                background: #f8f9fa;
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
            }
            .priority-high {
                border-left: 4px solid #dc3545;
            }
            .priority-medium {
                border-left: 4px solid #ffc107;
            }
            .priority-low {
                border-left: 4px solid #28a745;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔔 New Contact Form Submission</h1>
                <p>Someone has submitted a message through the website</p>
            </div>
            
            <div class="content">
                <div class="contact-details ${getPriorityClass(contactData.subject)}">
                    <h3>Contact Information:</h3>
                    <p><strong>Name:</strong> ${contactData.firstName} ${contactData.lastName}</p>
                    <p><strong>Email:</strong> <a href="mailto:${contactData.email}">${contactData.email}</a></p>
                    ${contactData.phone ? `<p><strong>Phone:</strong> <a href="tel:${contactData.phone}">${contactData.phone}</a></p>` : ''}
                    <p><strong>Subject:</strong> ${contactData.subject}</p>
                    <p><strong>Newsletter Signup:</strong> ${contactData.newsletter === 'on' ? 'Yes ✅' : 'No'}</p>
                    <p><strong>Submitted:</strong> ${new Date().toLocaleString()}</p>
                    ${contactData.id ? `<p><strong>Contact ID:</strong> #${contactData.id}</p>` : ''}
                </div>
                
                <div class="contact-details">
                    <h3>Message:</h3>
                    <p style="background: white; padding: 15px; border-radius: 5px; font-style: italic;">
                        "${contactData.message}"
                    </p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="mailto:${contactData.email}?subject=Re: ${contactData.subject}" 
                       style="display: inline-block; background: linear-gradient(135deg, #ff8306 0%, #ffa726 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 25px; font-weight: bold; margin-right: 10px;">
                        Reply to Customer
                    </a>
                </div>
                
                <p style="font-size: 12px; color: #666; text-align: center;">
                    This is an automated notification from your PLWG'S Creative Apparel website contact form.
                </p>
            </div>
        </div>
    </body>
    </html>
  `;

  // Send to all admin emails
  const adminEmails = [process.env.ADMIN_EMAIL, 'letsgetcreative@myyahoo.com', 'PlwgsCreativeApparel@yahoo.com'].filter(Boolean);
  
  await sendResendEmail(
    adminEmails,
    `🔔 New Contact Form: ${contactData.subject} - ${contactData.firstName} ${contactData.lastName}`,
    adminEmailHTML
  );
  logger.info(`✅ Admin contact notification sent to ${adminEmails.join(', ')}`);
}

// Helper function to determine priority class based on subject
function getPriorityClass(subject) {
  const highPriority = ['technical-support', 'order-inquiry', 'bulk-order'];
  const mediumPriority = ['custom-design', 'partnership'];
  
  if (highPriority.includes(subject)) return 'priority-high';
  if (mediumPriority.includes(subject)) return 'priority-medium';
  return 'priority-low';
}

// =============================================================================
// EXISTING NEWSLETTER ENDPOINTS
// =============================================================================

// Newsletter subscription validation
const validateNewsletterSubscription = [
  body('email').isEmail().withMessage('Please enter a valid email address'),
  body('name').optional().isString().trim().withMessage('Name must be a string'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Newsletter subscription endpoint
app.post('/api/subscribe', validateNewsletterSubscription, async (req, res) => {
  try {
    const { email, name } = req.body;

    // Check if subscriber already exists
    const existingSubscriber = await pool.query(
      'SELECT * FROM subscribers WHERE email = $1',
      [email]
    );

    if (existingSubscriber.rows.length > 0) {
      const subscriber = existingSubscriber.rows[0];
      if (subscriber.is_active) {
        return res.status(400).json({ error: 'Email already subscribed' });
      } else {
        // Reactivate subscription
        await pool.query(
          'UPDATE subscribers SET is_active = true, welcome_email_sent = false WHERE email = $1',
          [email]
        );
        await sendWelcomeEmail(email, name || subscriber.name);
        return res.json({ 
          success: true, 
          message: 'Successfully re-subscribed to newsletter!',
          subscriber: { ...subscriber, is_active: true }
        });
      }
    }

    // Insert new subscriber
    const newSubscriber = await pool.query(
      'INSERT INTO subscribers (email, name) VALUES ($1, $2) RETURNING *',
      [email, name || null]
    );

    // Send welcome email
    await sendWelcomeEmail(email, name);

    // Update welcome email sent status
    await pool.query(
      'UPDATE subscribers SET welcome_email_sent = true WHERE id = $1',
      [newSubscriber.rows[0].id]
    );

    res.json({ 
      success: true, 
      message: 'Successfully subscribed to newsletter!',
      subscriber: newSubscriber.rows[0]
    });

  } catch (error) {
    logger.error('Error subscribing:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Send welcome email function
async function sendWelcomeEmail(email, name) {
  const welcomeEmailHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to PlwgsCreativeApparel!</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
                max-width: 600px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                overflow: hidden;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 28px;
                font-weight: 700;
            }
            .header p {
                margin: 10px 0 0 0;
                font-size: 16px;
                opacity: 0.9;
            }
            .content {
                padding: 40px 30px;
            }
            .welcome-text {
                font-size: 18px;
                color: #333;
                margin-bottom: 25px;
            }
            .highlight-box {
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                color: white;
                padding: 25px;
                border-radius: 10px;
                margin: 25px 0;
                text-align: center;
            }
            .discount-code {
                font-size: 24px;
                font-weight: bold;
                background: white;
                color: #f5576c;
                padding: 10px 20px;
                border-radius: 5px;
                display: inline-block;
                margin: 10px 0;
            }
            .features {
                margin: 30px 0;
            }
            .feature {
                display: flex;
                align-items: center;
                margin: 15px 0;
                padding: 15px;
                background: #f8f9fa;
                border-radius: 8px;
            }
            .feature-icon {
                width: 40px;
                height: 40px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                margin-right: 15px;
                color: white;
                font-weight: bold;
            }
            .cta-button {
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 15px 30px;
                text-decoration: none;
                border-radius: 25px;
                font-weight: bold;
                margin: 20px 0;
                text-align: center;
            }
            .footer {
                background: #f8f9fa;
                padding: 30px;
                text-align: center;
                color: #666;
            }
            .social-links {
                margin: 20px 0;
            }
            .social-links a {
                color: #667eea;
                text-decoration: none;
                margin: 0 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎉 Welcome to PlwgsCreativeApparel!</h1>
                <p>Your journey to unique, custom apparel starts here</p>
            </div>
            
            <div class="content">
                <div class="welcome-text">
                    <p>Hi ${name || 'there'}!</p>
                    <p>Welcome to the PlwgsCreativeApparel family! We're thrilled to have you join our community of creative individuals who love to express themselves through unique, custom-designed apparel.</p>
                </div>

                <div class="highlight-box">
                    <h2>🎁 Your Welcome Gift</h2>
                    <p>As a special welcome, enjoy <strong>20% OFF</strong> your first order!</p>
                    <div class="discount-code">PROMOCODE20</div>
                    <p>Use this code at checkout for instant savings!</p>
                </div>

                <div class="features">
                    <h3>🌟 What Makes Us Special</h3>
                    
                    <div class="feature">
                        <div class="feature-icon">🎨</div>
                        <div>
                            <strong>Custom Designs</strong><br>
                            Create your own unique designs or let us bring your ideas to life
                        </div>
                    </div>
                    
                    <div class="feature">
                        <div class="feature-icon">👕</div>
                        <div>
                            <strong>Quality Materials</strong><br>
                            Premium fabrics and printing techniques for lasting quality
                        </div>
                    </div>
                    
                    <div class="feature">
                        <div class="feature-icon">🚚</div>
                        <div>
                            <strong>Fast Shipping</strong><br>
                            Quick turnaround times and reliable delivery
                        </div>
                    </div>
                    
                    <div class="feature">
                        <div class="feature-icon">💝</div>
                        <div>
                            <strong>Personalized Service</strong><br>
                            Dedicated support for custom orders and special requests
                        </div>
                    </div>
                </div>

                <div style="text-align: center;">
                    <a href="https://plwgscreativeapparel.com/pages/shop.html" class="cta-button">
                        🛍️ Start Shopping Now
                    </a>
                </div>

                <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                    <h4>💡 Custom Design Requests</h4>
                    <p>Have a specific design in mind? We love creating custom pieces! Contact us for:</p>
                    <ul style="text-align: left;">
                        <li>Personalized family shirts</li>
                        <li>Event-specific designs</li>
                        <li>Corporate branding</li>
                        <li>Special occasion apparel</li>
                    </ul>
                </div>
            </div>

            <div class="footer">
                <p><strong>Stay Connected</strong></p>
                <div class="social-links">
                    <a href="#">Instagram</a> |
                    <a href="#">Facebook</a> |
                    <a href="#">Twitter</a>
                </div>
                <p>Questions? Contact us at <a href="mailto:support@plwgscreativeapparel.com">support@plwgscreativeapparel.com</a></p>
                <p style="font-size: 12px; margin-top: 20px;">
                    You're receiving this email because you subscribed to our newsletter.<br>
                    <a href="#">Unsubscribe</a> | <a href="#">Privacy Policy</a>
                </p>
            </div>
        </div>
    </body>
    </html>
  `;

  try {
    await sendResendEmail(
      email,
      '🎉 Welcome to PlwgsCreativeApparel - Your 20% OFF Code Inside!',
      welcomeEmailHTML
    );
    logger.info(`✅ Welcome email sent to ${email}`);
  } catch (error) {
    logger.error(`❌ Error sending welcome email to ${email}:`, error);
  }
}

// Send customer confirmation email function
async function sendCustomerConfirmationEmail(customRequest) {
  const customerEmailHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Custom Design Request Confirmation - PlwgsCreativeApparel</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
                max-width: 700px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                overflow: hidden;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 28px;
                font-weight: 700;
            }
            .header p {
                margin: 10px 0 0 0;
                font-size: 16px;
                opacity: 0.9;
            }
            .content {
                padding: 40px 30px;
            }
            .request-summary {
                background: #f8f9fa;
                border-radius: 10px;
                padding: 25px;
                margin: 25px 0;
            }
            .detail-row {
                display: flex;
                justify-content: space-between;
                margin: 10px 0;
                padding: 8px 0;
                border-bottom: 1px solid #e9ecef;
            }
            .detail-row:last-child {
                border-bottom: none;
            }
            .detail-label {
                font-weight: bold;
                color: #495057;
            }
            .detail-value {
                color: #333;
                text-align: right;
            }
            .next-steps {
                background: #e3f2fd;
                border-left: 4px solid #2196f3;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
            }
            .cta-button {
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 15px 30px;
                text-decoration: none;
                border-radius: 25px;
                font-weight: bold;
                margin: 20px 0;
            }
            .footer {
                background: #f8f9fa;
                padding: 30px;
                text-align: center;
                color: #6c757d;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎨 Request Received!</h1>
                <p>Thank you for choosing PlwgsCreativeApparel for your custom design</p>
            </div>

            <div class="content">
                <p>Hi ${customRequest.customer_name},</p>
                
                <p>We're excited to work on your custom design! We've received your request and our team is already reviewing the details.</p>

                <div class="request-summary">
                    <h3>📋 Request Summary</h3>
                    
                    <div class="detail-row">
                        <span class="detail-label">Request ID:</span>
                        <span class="detail-value">#${customRequest.id}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Product Type:</span>
                        <span class="detail-value">${customRequest.request_type}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Quantity:</span>
                        <span class="detail-value">${customRequest.quantity}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Timeline:</span>
                        <span class="detail-value">${customRequest.timeline || 'Standard'}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Budget Range:</span>
                        <span class="detail-value">$${customRequest.estimated_budget}</span>
                    </div>
                </div>

                <div class="next-steps">
                    <h4>⏰ What Happens Next?</h4>
                    <ul style="text-align: left;">
                        <li><strong>Within 24 hours:</strong> You'll receive a detailed quote and timeline</li>
                        <li><strong>Within 2-3 days:</strong> Initial concept sketches and mockups</li>
                        <li><strong>Ongoing:</strong> Regular updates and collaboration throughout the process</li>
                    </ul>
                </div>

                <div style="text-align: center; margin: 30px 0;">
                </div>

                <p><strong>Questions?</strong> Don't hesitate to reply to this email or contact us directly.</p>
                
                <p>We can't wait to bring your vision to life!</p>
                
                <p>Best regards,<br>
                <strong>Lori & The PlwgsCreativeApparel Team</strong></p>
            </div>

            <div class="footer">
                <p><strong>PlwgsCreativeApparel</strong></p>
                <p>Custom Design Request #${customRequest.id}</p>
                <p>Submitted: ${new Date(customRequest.created_at).toLocaleString()}</p>
            </div>
        </div>
    </body>
    </html>
  `;

  try {
    await sendResendEmail(
      customRequest.customer_email,
      `🎨 Custom Design Request #${customRequest.id} Received - PlwgsCreativeApparel`,
      customerEmailHTML
    );
    logger.info(`✅ Customer confirmation email sent for request ${customRequest.id}`);
  } catch (error) {
    logger.error(`❌ Error sending customer confirmation email:`, error);
  }
}

// Send custom request email function
async function sendCustomRequestEmail(customRequest) {
  const customRequestEmailHTML = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>New Custom Design Request - PlwgsCreativeApparel</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 0;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .container {
                max-width: 700px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                overflow: hidden;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            }
            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 28px;
                font-weight: 700;
            }
            .header p {
                margin: 10px 0 0 0;
                font-size: 16px;
                opacity: 0.9;
            }
            .content {
                padding: 40px 30px;
            }
            .request-details {
                background: #f8f9fa;
                border-radius: 10px;
                padding: 25px;
                margin: 25px 0;
            }
            .detail-row {
                display: flex;
                justify-content: space-between;
                margin: 10px 0;
                padding: 8px 0;
                border-bottom: 1px solid #e9ecef;
            }
            .detail-row:last-child {
                border-bottom: none;
            }
            .detail-label {
                font-weight: bold;
                color: #495057;
            }
            .detail-value {
                color: #333;
                text-align: right;
            }
            .concept-box {
                background: #e3f2fd;
                border-left: 4px solid #2196f3;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
            }
            .cta-button {
                display: inline-block;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 15px 30px;
                text-decoration: none;
                border-radius: 25px;
                font-weight: bold;
                margin: 20px 0;
            }
            .footer {
                background: #f8f9fa;
                padding: 30px;
                text-align: center;
                color: #6c757d;
            }
            .priority-high {
                background: #fff3cd;
                border-left: 4px solid #ffc107;
            }
            .priority-rush {
                background: #f8d7da;
                border-left: 4px solid #dc3545;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎨 New Custom Design Request</h1>
                <p>You have a new custom design request from ${customRequest.customer_name}</p>
            </div>

            <div class="content">
                <div class="request-details ${customRequest.timeline === 'rush' || customRequest.timeline === 'express' ? 'priority-rush' : 'priority-high'}">
                    <h3>📋 Request Details</h3>
                    
                    <div class="detail-row">
                        <span class="detail-label">Customer Name:</span>
                        <span class="detail-value">${customRequest.customer_name}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Email:</span>
                        <span class="detail-value">${customRequest.customer_email}</span>
                    </div>
                    
                    ${customRequest.customer_phone ? `
                    <div class="detail-row">
                        <span class="detail-label">Phone:</span>
                        <span class="detail-value">${customRequest.customer_phone}</span>
                    </div>
                    ` : ''}
                    
                    <div class="detail-row">
                        <span class="detail-label">Timeline:</span>
                        <span class="detail-value">${customRequest.timeline}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Product Type:</span>
                        <span class="detail-value">${customRequest.request_type}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Quantity:</span>
                        <span class="detail-value">${customRequest.quantity}</span>
                    </div>
                    
                    <div class="detail-row">
                        <span class="detail-label">Budget Range:</span>
                        <span class="detail-value">$${customRequest.estimated_budget}</span>
                    </div>
                    
                    ${customRequest.size_requirements ? `
                    <div class="detail-row">
                        <span class="detail-label">Size Requirements:</span>
                        <span class="detail-value">${Array.isArray(customRequest.size_requirements) ? customRequest.size_requirements.join(', ') : customRequest.size_requirements}</span>
                    </div>
                    ` : ''}
                    
                    ${customRequest.color_preferences ? `
                    <div class="detail-row">
                        <span class="detail-label">Color Preferences:</span>
                        <span class="detail-value">${customRequest.color_preferences}</span>
                    </div>
                    ` : ''}
                    
                    ${customRequest.style_preferences ? `
                    <div class="detail-row">
                        <span class="detail-label">Style Preferences:</span>
                        <span class="detail-value">${Array.isArray(customRequest.style_preferences) ? customRequest.style_preferences.join(', ') : customRequest.style_preferences}</span>
                    </div>
                    ` : ''}
                </div>

                <div class="concept-box">
                    <h4>💡 Design Concept</h4>
                    <p>${customRequest.concept_description}</p>
                </div>

                ${customRequest.additional_notes ? `
                <div class="concept-box">
                    <h4>📝 Additional Notes</h4>
                    <p>${customRequest.additional_notes}</p>
                </div>
                ` : ''}

                <div style="text-align: center; margin: 30px 0;">
                    <a href="https://plwgscreativeapparel.com/pages/admin.html" class="cta-button">
                        📊 View in Admin Dashboard
                    </a>
                </div>

                <div style="background: #fff3cd; border-radius: 10px; padding: 20px; margin: 20px 0;">
                    <h4>⏰ Action Required</h4>
                    <p><strong>Please review this request and respond to the customer within 24 hours.</strong></p>
                    <ul style="text-align: left;">
                        <li>Review the design concept and requirements</li>
                        <li>Prepare a detailed quote</li>
                        <li>Send initial mockup or concept sketches</li>
                        <li>Set up timeline and milestones</li>
                    </ul>
                </div>
            </div>

            <div class="footer">
                <p><strong>PlwgsCreativeApparel</strong></p>
                <p>Custom Design Request - ID: ${customRequest.id}</p>
                <p>Submitted: ${new Date(customRequest.created_at).toLocaleString()}</p>
            </div>
        </div>
    </body>
    </html>
  `;

  // Send to all admin emails
  const adminEmails = [process.env.ADMIN_EMAIL, 'letsgetcreative@myyahoo.com', 'PlwgsCreativeApparel@yahoo.com'].filter(Boolean);
  
  try {
    await sendResendEmail(
      adminEmails,
      `🎨 New Custom Design Request from ${customRequest.customer_name}`,
      customRequestEmailHTML
    );
    logger.info(`✅ Custom request email sent to ${adminEmails.join(', ')} for request ${customRequest.id}`);
    } catch (error) {
    logger.error(`❌ Error sending custom request email:`, error);
  }
}

// Get all subscribers (admin endpoint)
app.get('/api/subscribers', authenticateToken, async (req, res) => {
  const dbCheck = checkDatabase();
  if (!dbCheck.available) {
    // Return mock data for development
    return res.json({ subscribers: [] });
  }

  try {
    const result = await pool.query('SELECT * FROM subscribers ORDER BY subscribed_at DESC');
    res.json({ subscribers: result.rows });
  } catch (error) {
    logger.error('Error fetching subscribers:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Unsubscribe validation
const validateUnsubscribe = [
  body('email').isEmail().withMessage('Please enter a valid email address'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Unsubscribe endpoint
app.post('/api/unsubscribe', validateUnsubscribe, async (req, res) => {
  try {
    const { email } = req.body;

    const result = await pool.query(
      'UPDATE subscribers SET is_active = false WHERE email = $1 RETURNING *',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Email not found' });
    }

    res.json({ success: true, message: 'Successfully unsubscribed' });
  } catch (error) {
    logger.error('Error unsubscribing:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// =============================================================================
// CUSTOMER DASHBOARD ENDPOINTS
// =============================================================================

// Customer authentication middleware
const authenticateCustomer = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'customer') {
      return res.status(403).json({ error: 'Customer access required' });
    }
    req.customer = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Customer registration/login
const validateRegistration = [
  body('email').isEmail().withMessage('Please enter a valid email address.'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.'),
  body('first_name').if(body('action').equals('register')).notEmpty().trim().withMessage('First name is required for registration'),
  body('last_name').if(body('action').equals('register')).notEmpty().trim().withMessage('Last name is required for registration'),
  (req, res, next) => {
    if (req.body.action !== 'register') {
      return next();
    }
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];
app.post('/api/customer/auth', validateRegistration, async (req, res) => {
  try {
    const { email, password, action = 'login', first_name, last_name } = req.body;

    if (action === 'google_login') {
      // Handle Google OAuth login
      const { google_id, profile_picture } = req.body;
      
      // Check if customer already exists
      let existingCustomer = await pool.query(
        'SELECT * FROM customers WHERE email = $1 OR google_id = $2',
        [email, google_id]
      );

      let customer;

      if (existingCustomer.rows.length === 0) {
        // Create new customer with Google data
        const newCustomer = await pool.query(`
          INSERT INTO customers (email, first_name, last_name, name, google_id, profile_picture, email_verified)
          VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *
        `, [
          email, 
          first_name, 
          last_name, 
          `${first_name} ${last_name}`, 
          google_id, 
          profile_picture, 
          true
        ]);

        customer = newCustomer.rows[0];

        // Create default style profile
        await pool.query(`
          INSERT INTO customer_style_profile (customer_id)
          VALUES ($1)
        `, [customer.id]);

      } else {
        // Update existing customer with Google data if needed
        customer = existingCustomer.rows[0];
        
        if (!customer.google_id) {
          await pool.query(`
            UPDATE customers 
            SET google_id = $1, profile_picture = $2, email_verified = $3
            WHERE id = $4
          `, [google_id, profile_picture, true, customer.id]);
        }
      }

      const token = jwt.sign(
        { id: customer.id, email, role: 'customer' },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        token,
        customer: {
          id: customer.id,
          email: customer.email,
          name: customer.name,
          profile_picture: customer.profile_picture,
          loyalty_points: customer.loyalty_points,
          loyalty_tier: customer.loyalty_tier
        }
      });
    } else if (action === 'register') {
      // Check if customer already exists
      const existingCustomer = await pool.query(
        'SELECT * FROM customers WHERE email = $1',
        [email]
      );

      if (existingCustomer.rows.length > 0) {
        return res.status(400).json({ error: 'Email already registered' });
      }

      // Hash password and create customer
      const hashedPassword = await bcrypt.hash(password, 12);
      
      const newCustomer = await pool.query(`
        INSERT INTO customers (email, password, first_name, last_name, name)
        VALUES ($1, $2, $3, $4, $5) RETURNING *
      `, [email, hashedPassword, first_name, last_name, `${first_name} ${last_name}`]);

      const customer = newCustomer.rows[0];
      
      // Create default style profile
      await pool.query(`
        INSERT INTO customer_style_profile (customer_id)
        VALUES ($1)
      `, [customer.id]);

      const token = jwt.sign(
        { id: customer.id, email, role: 'customer' },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        token,
        customer: {
          id: customer.id,
          email: customer.email,
          name: customer.name,
          loyalty_points: customer.loyalty_points,
          loyalty_tier: customer.loyalty_tier
        }
      });
    } else {
      // Login
      const customer = await pool.query(
        'SELECT * FROM customers WHERE email = $1',
        [email]
      );

      if (customer.rows.length === 0) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Check hashed password
      const isValidPassword = await bcrypt.compare(password, customer.rows[0].password);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const customerData = customer.rows[0];
      const token = jwt.sign(
        { id: customerData.id, email, role: 'customer' },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        success: true,
        token,
        customer: {
          id: customerData.id,
          email: customerData.email,
          name: customerData.name,
          loyalty_points: customerData.loyalty_points,
          loyalty_tier: customerData.loyalty_tier
        }
      });
    }
  } catch (error) {
    logger.error('Customer auth error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get Google OAuth client ID for frontend
app.get('/api/config/google-client-id', (req, res) => {
  // Set CORS headers
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.json({ client_id: process.env.GOOGLE_CLIENT_ID });
});

// Handle preflight OPTIONS request for Google OAuth
app.options('/api/customer/auth/google', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(200);
});

// Handle Google OAuth callback (when user returns from Google)
console.log('📝 Registering OAuth callback route: GET /oauth/callback');
app.get('/oauth/callback', async (req, res) => {
  console.log('🔐 OAuth callback HIT - Route is working!');
  console.log('Query params:', req.query);
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

    console.log('✅ Authorization code received, exchanging for token...');
    logger.info('✅ Authorization code received, exchanging for token...');

    // Exchange code for access token
    // MUST match exactly what frontend sent (always HTTPS in production)
    const redirectUri = 'https://plwgscreativeapparel.com/oauth/callback';
    console.log('🔄 Token exchange params - Client ID:', process.env.GOOGLE_CLIENT_ID ? 'SET' : 'MISSING');
    console.log('🔄 Token exchange params - Client Secret:', process.env.GOOGLE_CLIENT_SECRET ? 'SET' : 'MISSING');
    console.log('🔄 Token exchange params - Redirect URI:', redirectUri);
    console.log('🔄 Token exchange params - Has code:', !!code);
    logger.info('🔄 Token exchange params:', {
      client_id: process.env.GOOGLE_CLIENT_ID ? 'SET' : 'MISSING',
      client_secret: process.env.GOOGLE_CLIENT_SECRET ? 'SET' : 'MISSING',
      redirect_uri: redirectUri,
      has_code: !!code
    });

    console.log('🌐 About to fetch token from Google...');
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri
      })
    });

    console.log('📡 Token response status:', tokenResponse.status);
    const tokenData = await tokenResponse.json();
    console.log('📡 Token data received:', JSON.stringify(tokenData));
    logger.info('📡 Token response:', { 
      status: tokenResponse.status,
      has_access_token: !!tokenData.access_token,
      error: tokenData.error
    });
    
    console.log('🔍 Checking if access_token exists...');
    if (!tokenData.access_token) {
      console.error('❌ No access token in response!');
      throw new Error(`Token exchange failed: ${tokenData.error || 'No access token'} - ${tokenData.error_description || ''}`);
    }

    console.log('✅ Access token confirmed, fetching user info...');
    logger.info('✅ Access token received, fetching user info...');

    // Get user info from Google
    console.log('🌐 Fetching user info from Google...');
    const userResponse = await fetch(`https://www.googleapis.com/oauth2/v2/userinfo?access_token=${tokenData.access_token}`);
    console.log('📡 User info response status:', userResponse.status);
    const userData = await userResponse.json();
    console.log('✅ User data received:', JSON.stringify(userData));
    logger.info('✅ User data received:', { email: userData.email });

    // Send success message to parent window
    console.log('📤 Sending success message to popup...');
    res.send(`
      <script>
        console.log('✅ OAuth success! Closing popup and sending message...');
        window.opener.postMessage({
          success: true,
          user: ${JSON.stringify(userData)},
          token: '${tokenData.access_token}'
        }, '*');
        window.close();
      </script>
    `);

  } catch (error) {
    logger.error('❌ OAuth callback error:', error);
    res.send(`
      <script>
        window.opener.postMessage({error: 'OAuth failed: ${error.message}'}, '*');
        window.close();
      </script>
    `);
  }
});

// Google OAuth login endpoint
app.post('/api/customer/auth/google', async (req, res) => {
  // Set CORS headers
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: 'Google credential is required' });
    }

    // Verify the Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, given_name, family_name, picture, email_verified } = payload;

    if (!email_verified) {
      return res.status(400).json({ error: 'Google email not verified' });
    }

    // Check if customer already exists
    let customerResult = await pool.query(
      'SELECT * FROM customers WHERE email = $1',
      [email]
    );

    let customer;

    if (customerResult.rows.length === 0) {
      // Create new customer with Google data
      const newCustomer = await pool.query(`
        INSERT INTO customers (email, first_name, last_name, name, google_id, profile_picture, email_verified)
        VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *
      `, [
        email, 
        given_name, 
        family_name, 
        `${given_name} ${family_name}`, 
        payload.sub, 
        picture, 
        email_verified
      ]);

      customer = newCustomer.rows[0];

      // Create default style profile for new customer
      await pool.query(`
        INSERT INTO customer_style_profile (customer_id)
        VALUES ($1)
      `, [customer.id]);

    } else {
      // Update existing customer with Google data if needed
      customer = customerResult.rows[0];
      
      if (!customer.google_id) {
        await pool.query(`
          UPDATE customers 
          SET google_id = $1, profile_picture = $2, email_verified = $3
          WHERE id = $4
        `, [payload.sub, picture, email_verified, customer.id]);
      }
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: customer.id, email, role: 'customer' },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      customer: {
        id: customer.id,
        email: customer.email,
        name: customer.name,
        profile_picture: customer.profile_picture,
        loyalty_points: customer.loyalty_points,
        loyalty_tier: customer.loyalty_tier
      }
    });

  } catch (error) {
    logger.error('Google OAuth error:', error);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// Get customer profile
app.get('/api/customer/profile', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    
    const customerResult = await pool.query(`
      SELECT * FROM customers WHERE id = $1
    `, [customerId]);
    
    if (customerResult.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    const customer = customerResult.rows[0];
    
    // Get customer addresses
    const addressesResult = await pool.query(`
      SELECT * FROM customer_addresses WHERE customer_id = $1 ORDER BY is_default DESC
    `, [customerId]);
    
    // Get customer preferences
    const preferencesResult = await pool.query(`
      SELECT * FROM customer_preferences WHERE customer_id = $1
    `, [customerId]);
    
    // Get style profile
    const styleProfileResult = await pool.query(`
      SELECT * FROM customer_style_profile WHERE customer_id = $1
    `, [customerId]);
    
    res.json({
      customer,
      addresses: addressesResult.rows,
      preferences: preferencesResult.rows,
      style_profile: styleProfileResult.rows[0] || null
    });
  } catch (error) {
    logger.error('Error fetching customer profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update customer profile
app.put('/api/customer/profile', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { first_name, last_name, phone, birthday, addresses, preferences } = req.body;
    
    // Update customer info (preserve existing values when null/undefined)
    await pool.query(`
      UPDATE customers 
      SET 
        first_name = COALESCE($1, first_name),
        last_name = COALESCE($2, last_name),
        phone = COALESCE($3, phone),
        birthday = COALESCE($4, birthday),
        name = CASE 
          WHEN $1 IS NOT NULL OR $2 IS NOT NULL THEN CONCAT(COALESCE($1, ''), ' ', COALESCE($2, ''))
          ELSE name
        END,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $5
    `, [first_name ?? null, last_name ?? null, phone ?? null, birthday ?? null, customerId]);
    
    // Update addresses if provided
    if (addresses && Array.isArray(addresses)) {
      // Clear existing addresses
      await pool.query('DELETE FROM customer_addresses WHERE customer_id = $1', [customerId]);
      
      // Insert new addresses
      for (const address of addresses) {
        await pool.query(`
          INSERT INTO customer_addresses (customer_id, address_type, first_name, last_name, address_line1, address_line2, city, state, postal_code, country, is_default)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `, [customerId, address.address_type, address.first_name, address.last_name, address.address_line1, address.address_line2, address.city, address.state, address.postal_code, address.country, address.is_default]);
      }
    }
    
    // Update preferences if provided
    if (preferences && Array.isArray(preferences)) {
      for (const pref of preferences) {
        await pool.query(`
          INSERT INTO customer_preferences (customer_id, preference_type, preference_value)
          VALUES ($1, $2, $3)
          ON CONFLICT (customer_id, preference_type) 
          DO UPDATE SET preference_value = $3, updated_at = CURRENT_TIMESTAMP
        `, [customerId, pref.preference_type, pref.preference_value]);
      }
    }
    
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch (error) {
    logger.error('Error updating customer profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get customer orders
app.get('/api/customer/orders', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { limit = 10, offset = 0 } = req.query;
    
    const ordersResult = await pool.query(`
      SELECT o.*, 
             COUNT(oi.id) as item_count
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      WHERE o.customer_id = $1
      GROUP BY o.id
      ORDER BY o.created_at DESC
      LIMIT $2 OFFSET $3
    `, [customerId, limit, offset]);
    
    // Get order items for each order
    const ordersWithItems = await Promise.all(
      ordersResult.rows.map(async (order) => {
        const itemsResult = await pool.query(`
          SELECT * FROM order_items WHERE order_id = $1
        `, [order.id]);
        
        return {
          ...order,
          items: itemsResult.rows
        };
      })
    );
    
    res.json({ orders: ordersWithItems });
  } catch (error) {
    logger.error('Error fetching customer orders:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get a specific customer order with items and review flags
app.get('/api/customer/orders/:id', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { id } = req.params;

    // Fetch order and ensure ownership
    const orderResult = await pool.query(`
      SELECT * FROM orders WHERE id = $1 AND customer_id = $2
    `, [id, customerId]);
    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }
    const order = orderResult.rows[0];

    // Items
    const itemsResult = await pool.query(`
      SELECT * FROM order_items WHERE order_id = $1
    `, [id]);
    const items = itemsResult.rows;

    // Reviews by product for this customer
    const productIds = items.map(i => i.product_id).filter(Boolean);
    let reviewsByProduct = {};
    if (productIds.length > 0) {
      const r = await pool.query(`
        SELECT product_id, id, rating, status
        FROM product_reviews
        WHERE customer_id = $1 AND product_id = ANY($2::int[])
      `, [customerId, productIds]);
      for (const row of r.rows) {
        reviewsByProduct[row.product_id] = { id: row.id, rating: row.rating, status: row.status };
      }
    }

    res.json({ order, items, reviewsByProduct });
  } catch (error) {
    logger.error('Error fetching order details:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Customer review validation
const validateCustomerReview = [
  body('product_id').isInt({ min: 1 }).withMessage('Product ID must be a positive integer'),
  body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5'),
  body('order_id').optional().isInt({ min: 1 }).withMessage('Order ID must be a positive integer'),
  body('title').optional().isString().trim().isLength({ max: 200 }).withMessage('Title must be a string with maximum 200 characters'),
  body('body').optional().isString().trim().isLength({ max: 1000 }).withMessage('Review body must be a string with maximum 1000 characters'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Create or update a product review by a customer
app.post('/api/customer/reviews', authenticateCustomer, validateCustomerReview, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { product_id, order_id, rating, title, body, images } = req.body || {};

    // If order_id provided, verify ownership and product inclusion
    if (order_id) {
      const ownOrder = await pool.query(`SELECT 1 FROM orders WHERE id = $1 AND customer_id = $2`, [order_id, customerId]);
      if (ownOrder.rows.length === 0) {
        return res.status(403).json({ error: 'Order does not belong to customer' });
      }
      const hasProduct = await pool.query(`SELECT 1 FROM order_items WHERE order_id = $1 AND product_id = $2`, [order_id, product_id]);
      if (hasProduct.rows.length === 0) {
        return res.status(400).json({ error: 'Product not found in given order' });
      }
    }

    // Upsert one review per product per customer
    const upsert = await pool.query(`
      INSERT INTO product_reviews (product_id, customer_id, order_id, rating, title, body, images)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (customer_id, product_id)
      DO UPDATE SET
        order_id = EXCLUDED.order_id,
        rating = EXCLUDED.rating,
        title = EXCLUDED.title,
        body = EXCLUDED.body,
        images = EXCLUDED.images,
        updated_at = CURRENT_TIMESTAMP
      RETURNING id
    `, [product_id, customerId, order_id || null, rating, title || null, body || null, images ? JSON.stringify(images) : null]);

    res.json({ success: true, id: upsert.rows[0].id });
  } catch (error) {
    if (error && error.code === '23514') { // CHECK violation
      return res.status(400).json({ error: 'Invalid rating' });
    }
    logger.error('Error creating review:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
// Get customer addresses
app.get('/api/customer/addresses', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;

    const addressesResult = await pool.query(`
      SELECT * FROM customer_addresses 
      WHERE customer_id = $1 
      ORDER BY is_default DESC, created_at DESC
    `, [customerId]);

    res.json({ addresses: addressesResult.rows });
  } catch (error) {
    console.error('Error fetching addresses:', error);
    res.status(500).json({ error: 'Failed to fetch addresses' });
  }
});

// Create new customer address
app.post('/api/customer/addresses', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { 
      address_type, 
      first_name, 
      last_name, 
      address_line1, 
      address_line2, 
      city, 
      state, 
      postal_code, 
      country, 
      is_default 
    } = req.body;

    // If this is set as default, remove default from other addresses
    if (is_default) {
      await pool.query(
        'UPDATE customer_addresses SET is_default = false WHERE customer_id = $1',
        [customerId]
      );
    }

    const result = await pool.query(`
      INSERT INTO customer_addresses (
        customer_id, address_type, first_name, last_name, 
        address_line1, address_line2, city, state, 
        postal_code, country, is_default
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
      RETURNING *
    `, [
      customerId, address_type || 'Home', first_name, last_name,
      address_line1, address_line2, city, state,
      postal_code, country || 'United States', is_default || false
    ]);

    logger.info(`✅ Address created for customer ${customerId}`);
    res.json({ success: true, address: result.rows[0] });
  } catch (error) {
    logger.error('Error creating customer address:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update customer address
app.put('/api/customer/addresses/:id', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const addressId = req.params.id;
    const { 
      address_type, 
      first_name, 
      last_name, 
      address_line1, 
      address_line2, 
      city, 
      state, 
      postal_code, 
      country, 
      is_default 
    } = req.body;

    // Verify address belongs to customer
    const existingAddress = await pool.query(
      'SELECT * FROM customer_addresses WHERE id = $1 AND customer_id = $2',
      [addressId, customerId]
    );

    if (existingAddress.rows.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }

    // If this is set as default, remove default from other addresses
    if (is_default) {
      await pool.query(
        'UPDATE customer_addresses SET is_default = false WHERE customer_id = $1 AND id != $2',
        [customerId, addressId]
      );
    }

    const result = await pool.query(`
      UPDATE customer_addresses SET
        address_type = COALESCE($1, address_type),
        first_name = COALESCE($2, first_name),
        last_name = COALESCE($3, last_name),
        address_line1 = COALESCE($4, address_line1),
        address_line2 = COALESCE($5, address_line2),
        city = COALESCE($6, city),
        state = COALESCE($7, state),
        postal_code = COALESCE($8, postal_code),
        country = COALESCE($9, country),
        is_default = COALESCE($10, is_default)
      WHERE id = $11 AND customer_id = $12
      RETURNING *
    `, [
      address_type, first_name, last_name, address_line1, address_line2,
      city, state, postal_code, country, is_default,
      addressId, customerId
    ]);

    logger.info(`✅ Address ${addressId} updated for customer ${customerId}`);
    res.json({ success: true, address: result.rows[0] });
  } catch (error) {
    logger.error('Error updating customer address:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete customer address
app.delete('/api/customer/addresses/:id', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const addressId = req.params.id;

    // Verify address belongs to customer
    const existingAddress = await pool.query(
      'SELECT * FROM customer_addresses WHERE id = $1 AND customer_id = $2',
      [addressId, customerId]
    );

    if (existingAddress.rows.length === 0) {
      return res.status(404).json({ error: 'Address not found' });
    }

    await pool.query(
      'DELETE FROM customer_addresses WHERE id = $1 AND customer_id = $2',
      [addressId, customerId]
    );

    logger.info(`✅ Address ${addressId} deleted for customer ${customerId}`);
    res.json({ success: true, message: 'Address deleted successfully' });
  } catch (error) {
    logger.error('Error deleting customer address:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get customer wishlist
app.get('/api/customer/wishlist', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    
    const wishlistResult = await pool.query(`
      SELECT w.*, p.*
      FROM wishlist w
      JOIN products p ON w.product_id = p.id
      WHERE w.customer_id = $1
      ORDER BY w.added_at DESC
    `, [customerId]);
    
    res.json({ wishlist: wishlistResult.rows });
  } catch (error) {
    logger.error('Error fetching wishlist:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Wishlist validation
const validateWishlistAdd = [
  body('product_id').isInt({ min: 1 }).withMessage('Product ID must be a positive integer'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Add to wishlist
app.post('/api/customer/wishlist', authenticateCustomer, validateWishlistAdd, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { product_id } = req.body;
    
    // Check if product exists
    const productResult = await pool.query('SELECT * FROM products WHERE id = $1', [product_id]);
    if (productResult.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    // Add to wishlist
    await pool.query(`
      INSERT INTO wishlist (customer_id, product_id)
      VALUES ($1, $2)
      ON CONFLICT (customer_id, product_id) DO NOTHING
    `, [customerId, product_id]);
    
    res.json({ success: true, message: 'Added to wishlist' });
  } catch (error) {
    logger.error('Error adding to wishlist:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove from wishlist
app.delete('/api/customer/wishlist/:product_id', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { product_id } = req.params;
    
    await pool.query(`
      DELETE FROM wishlist WHERE customer_id = $1 AND product_id = $2
    `, [customerId, product_id]);
    
    res.json({ success: true, message: 'Removed from wishlist' });
  } catch (error) {
    logger.error('Error removing from wishlist:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get customer loyalty info
app.get('/api/customer/loyalty', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    
    // Get customer loyalty data
    const customerResult = await pool.query(`
      SELECT loyalty_points, loyalty_tier, total_orders, total_spent, average_order_value
      FROM customers WHERE id = $1
    `, [customerId]);
    
    if (customerResult.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }
    
    const customer = customerResult.rows[0];
    
    // Get available rewards
    const rewardsResult = await pool.query(`
      SELECT * FROM loyalty_rewards 
      WHERE customer_id = $1 AND is_redeemed = false AND (expires_at IS NULL OR expires_at > NOW())
      ORDER BY points_cost ASC
    `, [customerId]);
    
    // Get points history
    const historyResult = await pool.query(`
      SELECT * FROM loyalty_points_history 
      WHERE customer_id = $1 
      ORDER BY created_at DESC 
      LIMIT 10
    `, [customerId]);
    
    // Calculate tier progress
    const tierProgress = calculateTierProgress(customer.loyalty_points, customer.loyalty_tier);
    
    res.json({
      loyalty: customer,
      rewards: rewardsResult.rows,
      history: historyResult.rows,
      tier_progress: tierProgress
    });
  } catch (error) {
    logger.error('Error fetching loyalty info:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Loyalty redemption validation
const validateLoyaltyRedemption = [
  body('reward_id').isInt({ min: 1 }).withMessage('Reward ID must be a positive integer'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Redeem loyalty reward
app.post('/api/customer/loyalty/redeem', authenticateCustomer, validateLoyaltyRedemption, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { reward_id } = req.body;
    
    // Get reward details
    const rewardResult = await pool.query(`
      SELECT * FROM loyalty_rewards WHERE id = $1 AND customer_id = $2
    `, [reward_id, customerId]);
    
    if (rewardResult.rows.length === 0) {
      return res.status(404).json({ error: 'Reward not found' });
    }
    
    const reward = rewardResult.rows[0];
    
    // Check if customer has enough points
    const customerResult = await pool.query(`
      SELECT loyalty_points FROM customers WHERE id = $1
    `, [customerId]);
    
    if (customerResult.rows[0].loyalty_points < reward.points_cost) {
      return res.status(400).json({ error: 'Insufficient points' });
    }
    
    // Redeem reward
    await pool.query(`
      UPDATE loyalty_rewards SET is_redeemed = true, redeemed_at = CURRENT_TIMESTAMP WHERE id = $1
    `, [reward_id]);
    
    // Deduct points
    await pool.query(`
      UPDATE customers SET loyalty_points = loyalty_points - $1 WHERE id = $2
    `, [reward.points_cost, customerId]);
    
    // Add to points history
    await pool.query(`
      INSERT INTO loyalty_points_history (customer_id, points_change, change_type, description)
      VALUES ($1, $2, 'redemption', $3)
    `, [customerId, -reward.points_cost, `Redeemed: ${reward.reward_name}`]);
    
    res.json({ success: true, message: 'Reward redeemed successfully' });
  } catch (error) {
    logger.error('Error redeeming reward:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Style profile validation
const validateStyleProfile = [
  body('horror_aesthetic_percentage').optional().isFloat({ min: 0, max: 100 }).withMessage('Horror aesthetic percentage must be between 0 and 100'),
  body('pop_culture_percentage').optional().isFloat({ min: 0, max: 100 }).withMessage('Pop culture percentage must be between 0 and 100'),
  body('humor_sass_percentage').optional().isFloat({ min: 0, max: 100 }).withMessage('Humor sass percentage must be between 0 and 100'),
  body('favorite_colors').optional().isArray().withMessage('Favorite colors must be an array'),
  body('preferred_sizes').optional().isArray().withMessage('Preferred sizes must be an array'),
  body('fit_preference').optional().isString().withMessage('Fit preference must be a string'),
  body('length_preference').optional().isString().withMessage('Length preference must be a string'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Update customer style profile
app.put('/api/customer/style-profile', authenticateCustomer, validateStyleProfile, async (req, res) => {
  try {
    const customerId = req.customer.id;
    const { horror_aesthetic_percentage, pop_culture_percentage, humor_sass_percentage, favorite_colors, preferred_sizes, fit_preference, length_preference } = req.body;
    
    await pool.query(`
      INSERT INTO customer_style_profile (customer_id, horror_aesthetic_percentage, pop_culture_percentage, humor_sass_percentage, favorite_colors, preferred_sizes, fit_preference, length_preference)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (customer_id) 
      DO UPDATE SET 
        horror_aesthetic_percentage = $2,
        pop_culture_percentage = $3,
        humor_sass_percentage = $4,
        favorite_colors = $5,
        preferred_sizes = $6,
        fit_preference = $7,
        length_preference = $8,
        updated_at = CURRENT_TIMESTAMP
    `, [customerId, horror_aesthetic_percentage, pop_culture_percentage, humor_sass_percentage, favorite_colors, preferred_sizes, fit_preference, length_preference]);
    
    res.json({ success: true, message: 'Style profile updated successfully' });
  } catch (error) {
    logger.error('Error updating style profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get product recommendations for customer
app.get('/api/customer/recommendations', authenticateCustomer, async (req, res) => {
  try {
    const customerId = req.customer.id;
    
    // Get customer style profile
    const styleProfileResult = await pool.query(`
      SELECT * FROM customer_style_profile WHERE customer_id = $1
    `, [customerId]);
    
    const styleProfile = styleProfileResult.rows[0];
    
    // Get recommendations based on style preferences
    let recommendationsQuery = `
      SELECT * FROM products 
      WHERE is_active = true
    `;
    
    if (styleProfile) {
      // Add style-based filtering
      if (styleProfile.horror_aesthetic_percentage > 50) {
        recommendationsQuery += ` AND category = 'Horror'`;
      } else if (styleProfile.pop_culture_percentage > 50) {
        recommendationsQuery += ` AND category = 'Pop Culture'`;
      } else if (styleProfile.humor_sass_percentage > 50) {
        recommendationsQuery += ` AND category = 'Humor & Sass'`;
      }
    }
    
    recommendationsQuery += ` ORDER BY is_featured DESC, created_at DESC LIMIT 6`;
    
    const recommendationsResult = await pool.query(recommendationsQuery);
    
    res.json({ recommendations: recommendationsResult.rows });
  } catch (error) {
    logger.error('Error fetching recommendations:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper function to calculate tier progress
function calculateTierProgress(points, currentTier) {
  const tiers = {
    'Creative Rebel': { min: 0, max: 1000 },
    'Dark Visionary': { min: 1000, max: 2500 },
    'Gothic Master': { min: 2500, max: 5000 },
    'Horror Legend': { min: 5000, max: null }
  };
  
  const tier = tiers[currentTier];
  if (!tier) return { percentage: 0, pointsToNext: 0 };
  
  const progress = tier.max ? Math.min(100, ((points - tier.min) / (tier.max - tier.min)) * 100) : 100;
  const pointsToNext = tier.max ? Math.max(0, tier.max - points) : 0;
  
  return { percentage: Math.round(progress), pointsToNext };
}

// CART MANAGEMENT ENDPOINTS
// =============================================================================

// Calculate tiered shipping (Etsy-style)
async function calculateTieredShipping(cartItems) {
  try {
    const defaultAdditionalShipping = parseFloat(process.env.ADDITIONAL_ITEM_SHIPPING) || 4.00;
    
    // Get product details including shipping costs
    const productIds = [...new Set(cartItems.map(item => item.product_id))];
    const productsResult = await pool.query(`
      SELECT id, shipping_cost, additional_item_shipping 
      FROM products 
      WHERE id = ANY($1)
    `, [productIds]);
    
    const productShippingMap = {};
    productsResult.rows.forEach(p => {
      productShippingMap[p.id] = {
        first: parseFloat(p.shipping_cost) || 4.50,
        additional: p.additional_item_shipping ? parseFloat(p.additional_item_shipping) : defaultAdditionalShipping
      };
    });
    
    // Expand cart items by quantity (each item counts separately)
    const expandedItems = [];
    cartItems.forEach(item => {
      const shippingCosts = productShippingMap[item.product_id] || { first: 4.50, additional: defaultAdditionalShipping };
      for (let i = 0; i < item.quantity; i++) {
        expandedItems.push({
          product_id: item.product_id,
          firstItemCost: shippingCosts.first,
          additionalCost: shippingCosts.additional
        });
      }
    });
    
    // Sort by first item cost (highest first) to charge most expensive shipping first
    expandedItems.sort((a, b) => b.firstItemCost - a.firstItemCost);
    
    // Calculate total: first item gets full shipping, rest get additional rate
    let totalShipping = 0;
    if (expandedItems.length > 0) {
      totalShipping = expandedItems[0].firstItemCost; // First item
      for (let i = 1; i < expandedItems.length; i++) {
        totalShipping += expandedItems[i].additionalCost; // Additional items
      }
    }
    
    return parseFloat(totalShipping.toFixed(2));
  } catch (error) {
    logger.error('Error calculating tiered shipping:', error);
    // Fallback to simple calculation
    return 5.99;
  }
}

// Calculate shipping for cart items
app.post('/api/cart/calculate-shipping', authenticateCustomer, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const { items } = req.body;
    
    if (!items || items.length === 0) {
      return res.json({ shipping: 0 });
    }

    const shipping = await calculateTieredShipping(items);
    res.json({ shipping });
  } catch (error) {
    logger.error('Error calculating shipping:', error);
    res.status(500).json({ error: 'Failed to calculate shipping' });
  }
});

// Get customer's cart
app.get('/api/cart', authenticateCustomer, async (req, res) => {
  if (!pool) {
    return res.json({ items: [] });
  }

  try {
    const customerId = req.customer.id;
    
    const result = await pool.query(`
      SELECT 
        c.id,
        c.product_id,
        c.product_name,
        c.quantity,
        c.unit_price,
        c.size,
        c.color,
        c.image_url,
        c.custom_input,
        (c.quantity * c.unit_price) as total_price
      FROM cart c
      WHERE c.customer_id = $1
      ORDER BY c.created_at DESC
    `, [customerId]);

    res.json({ items: result.rows });
  } catch (error) {
    logger.error('Error fetching cart:', error);
    res.status(500).json({ error: 'Failed to fetch cart' });
  }
});

// Cart validation middleware
const validateCartAdd = [
  body('product_name').notEmpty().trim().withMessage('Product name is required'),
  body('quantity').isInt({ min: 1 }).withMessage('Quantity must be a positive integer'),
  body('unit_price').optional().isFloat({ min: 0 }).withMessage('Unit price must be a positive number'),
  body('size').optional().isString().withMessage('Size must be a string'),
  body('color').optional().isString().withMessage('Color must be a string'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

const validateCartUpdate = [
  body('quantity').isInt({ min: 0 }).withMessage('Quantity must be a non-negative integer'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Add item to cart
app.post('/api/cart/add', authenticateCustomer, validateCartAdd, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const customerId = req.customer.id;
    const { product_name, quantity, size, color, image_url, custom_input } = req.body;

    // Look up product ID, price, and image by name
    const productResult = await pool.query(`
      SELECT id, price, image_url FROM products WHERE name = $1
    `, [product_name]);

    if (productResult.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const product_id = productResult.rows[0].id;
    // Use unit_price from request body if provided, otherwise use product base price
    const unit_price = req.body.unit_price || productResult.rows[0].price;
    const product_image_url = productResult.rows[0].image_url;

    // Check if item already exists in cart
    const existingItem = await pool.query(`
      SELECT id, quantity FROM cart 
      WHERE customer_id = $1 AND product_id = $2 AND size = $3 AND color = $4
    `, [customerId, product_id, size || 'M', color || 'Black']);

    if (existingItem.rows.length > 0) {
      // Update quantity and custom input data
      const newQuantity = existingItem.rows[0].quantity + (quantity || 1);
      await pool.query(`
        UPDATE cart 
        SET quantity = $1, custom_input = $2, updated_at = CURRENT_TIMESTAMP 
        WHERE id = $3
      `, [newQuantity, custom_input ? JSON.stringify(custom_input) : null, existingItem.rows[0].id]);

      res.json({ message: 'Cart updated', item: { id: existingItem.rows[0].id, quantity: newQuantity } });
    } else {
      // Add new item
      const result = await pool.query(`
        INSERT INTO cart (customer_id, product_id, product_name, quantity, unit_price, size, color, image_url, custom_input)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
      `, [customerId, product_id, product_name, quantity || 1, unit_price, size || 'M', color || 'Black', product_image_url, custom_input ? JSON.stringify(custom_input) : null]);

      res.json({ message: 'Item added to cart', item: result.rows[0] });
    }
  } catch (error) {
    logger.error('Error adding to cart:', error);
    res.status(500).json({ error: 'Failed to add item to cart' });
  }
});

// Update cart item quantity
app.put('/api/cart/update/:id', authenticateCustomer, validateCartUpdate, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const customerId = req.customer.id;
    const cartItemId = req.params.id;
    const { quantity } = req.body;

    if (quantity <= 0) {
      // Remove item if quantity is 0 or less
      await pool.query(`
        DELETE FROM cart WHERE id = $1 AND customer_id = $2
      `, [cartItemId, customerId]);

      res.json({ message: 'Item removed from cart' });
    } else {
      // Update quantity
      const result = await pool.query(`
        UPDATE cart 
        SET quantity = $1, updated_at = CURRENT_TIMESTAMP 
        WHERE id = $2 AND customer_id = $3
        RETURNING *
      `, [quantity, cartItemId, customerId]);

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Cart item not found' });
      }

      res.json({ message: 'Cart updated', item: result.rows[0] });
    }
  } catch (error) {
    logger.error('Error updating cart:', error);
    res.status(500).json({ error: 'Failed to update cart' });
  }
});

// Remove item from cart
app.delete('/api/cart/remove/:id', authenticateCustomer, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const customerId = req.customer.id;
    const cartItemId = req.params.id;

    const result = await pool.query(`
      DELETE FROM cart WHERE id = $1 AND customer_id = $2
    `, [cartItemId, customerId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Cart item not found' });
    }

    res.json({ message: 'Item removed from cart' });
  } catch (error) {
    logger.error('Error removing from cart:', error);
    res.status(500).json({ error: 'Failed to remove item from cart' });
  }
});
// Clear customer's cart
app.delete('/api/cart/clear', authenticateCustomer, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const customerId = req.customer.id;

    await pool.query(`
      DELETE FROM cart WHERE customer_id = $1
    `, [customerId]);

    res.json({ message: 'Cart cleared' });
  } catch (error) {
    logger.error('Error clearing cart:', error);
    res.status(500).json({ error: 'Failed to clear cart' });
  }
});

// Get all products (public endpoint for admin uploads page)
app.get('/api/products/public', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const { category } = req.query;
    
    let query = `
      SELECT * FROM products 
      WHERE is_active = true
    `;
    
    const queryParams = [];
    
    if (category && category !== 'All Designs') {
      query += ` AND category = $1`;
      queryParams.push(category);
    }
    
    query += ` ORDER BY created_at DESC`;
    
    const result = await pool.query(query, queryParams);
    
    // Add basic schema for each product for SEO and optimize images
    const productsWithSchema = result.rows.map(product => {
      const optimizedProduct = optimizeProductImages(product);
      return {
        ...optimizedProduct,
        schema: generateProductSchema(optimizedProduct, { count: 0, average: 0, items: [] })
      };
    });
    
    res.json(productsWithSchema);
  } catch (error) {
    logger.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Get business schema for homepage SEO
app.get('/api/schema/business', async (req, res) => {
  try {
    const businessSchema = generateBusinessSchema();
    res.json(businessSchema);
  } catch (error) {
    logger.error('Error generating business schema:', error);
    res.status(500).json({ error: 'Failed to generate business schema' });
  }
});

// Get single product by ID (public endpoint for product detail pages)
app.get('/api/products/public/:id', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const productId = req.params.id;
    const result = await pool.query(`
      SELECT * FROM products WHERE id = $1 AND is_active = true
    `, [productId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const product = result.rows[0];

    // Reviews aggregate and items for public display
    const agg = await pool.query(`
      SELECT COUNT(*)::int AS count, COALESCE(AVG(rating),0)::float AS average
      FROM product_reviews
      WHERE product_id = $1 AND status = 'approved'
    `, [productId]);
    const { count, average } = agg.rows[0] || { count: 0, average: 0 };

    const itemsResult = await pool.query(`
      SELECT pr.id, pr.rating, pr.title, pr.body, pr.created_at,
             c.first_name, c.last_name, c.name AS full_name, c.email,
             a.first_name AS addr_first_name, a.last_name AS addr_last_name,
             CASE 
               WHEN COALESCE(NULLIF(TRIM(c.first_name), ''), NULLIF(TRIM(a.first_name), '')) IS NOT NULL
                 OR COALESCE(NULLIF(TRIM(c.last_name), ''), NULLIF(TRIM(a.last_name), '')) IS NOT NULL
                 THEN CONCAT(
                      COALESCE(NULLIF(TRIM(c.first_name), ''), NULLIF(TRIM(a.first_name), '')), ' ',
                      LEFT(COALESCE(NULLIF(TRIM(c.last_name), ''), NULLIF(TRIM(a.last_name), '')), 1)
                 )
               WHEN COALESCE(NULLIF(TRIM(c.name), ''), '') <> '' THEN c.name
               WHEN c.email IS NOT NULL AND POSITION('@' IN c.email) > 1 THEN SPLIT_PART(c.email, '@', 1)
               ELSE 'Customer'
             END AS display_name
      FROM product_reviews pr
      LEFT JOIN customers c ON pr.customer_id = c.id
      LEFT JOIN customer_addresses a ON a.customer_id = c.id AND a.is_default = true
      WHERE pr.product_id = $1 AND pr.status = 'approved'
      ORDER BY pr.created_at DESC
      LIMIT 20 OFFSET 0
    `, [productId]);

    // Generate enhanced schema markup for SEO
    const schema = generateProductSchema(product, { count, average, items: itemsResult.rows });
    
    res.json({ 
      product, 
      reviews: { count, average, items: itemsResult.rows },
      schema: schema
    });
  } catch (error) {
    logger.error('Error fetching product:', error);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// Get homepage hero products (up to 3, ordered by feature_rank)
app.get('/api/products/hero', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM products 
      WHERE is_active = true AND feature_rank IS NOT NULL
      ORDER BY feature_rank ASC
      LIMIT 3
    `);
    const optimizedProducts = result.rows.map(product => optimizeProductImages(product));
    res.json(optimizedProducts);
  } catch (error) {
    logger.error('Error fetching hero products:', error);
    res.status(500).json({ error: 'Failed to fetch hero products' });
  }
});

// Get homepage featured collections products (up to 6, ordered by featured_order)
app.get('/api/products/featured', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM products 
      WHERE is_active = true AND in_featured = true AND featured_order IS NOT NULL
      ORDER BY featured_order ASC
      LIMIT 6
    `);
    const optimizedProducts = result.rows.map(product => optimizeProductImages(product));
    res.json(optimizedProducts);
  } catch (error) {
    logger.error('Error fetching featured products:', error);
    res.status(500).json({ error: 'Failed to fetch featured products' });
  }
});

// Get top categories for shop dropdown (public endpoint)
app.get('/api/categories/top', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT category, COUNT(*) as product_count 
      FROM products 
      WHERE category IS NOT NULL AND category != '' AND is_active = true
      GROUP BY category 
      ORDER BY product_count DESC 
      LIMIT 4
    `);
    res.json(result.rows);
  } catch (error) {
    logger.error('Error fetching top categories:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// Get featured products for shop dropdown (public endpoint)
app.get('/api/products/dropdown-featured', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, price, image_url, category
      FROM products 
      WHERE is_active = true AND (is_featured = true OR in_featured = true)
      ORDER BY created_at DESC 
      LIMIT 3
    `);
    const optimizedProducts = result.rows.map(product => optimizeProductImages(product));
    res.json(optimizedProducts);
  } catch (error) {
    logger.error('Error fetching dropdown featured products:', error);
    res.status(500).json({ error: 'Failed to fetch featured products' });
  }
});

// Smart Product Recommendations API (authenticated users)
app.get('/api/recommendations', authenticateCustomer, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const customerId = req.customer.id;
    const limit = parseInt(req.query.limit) || 4; // Default to 4 recommendations
    
    let recommendations = [];
    
    // Strategy 1: Recently viewed products (from current session)
    const recentlyViewed = req.query.recentlyViewed ? JSON.parse(req.query.recentlyViewed) : [];
    if (recentlyViewed.length > 0) {
      // Ensure all values are integers
      const validIds = recentlyViewed.filter(id => Number.isInteger(Number(id))).map(id => Number(id));
      if (validIds.length > 0) {
        const recentProducts = await pool.query(`
          SELECT id, name, price, image_url, category
          FROM products 
          WHERE id = ANY($1) AND is_active = true
          ORDER BY array_position($1, id)
          LIMIT $2
        `, [validIds, limit]);
        
        if (recentProducts.rows.length > 0) {
          recommendations = recentProducts.rows;
        }
      }
    }
    
    // Strategy 2: Wishlist items (if we have enough recommendations)
    if (recommendations.length < limit) {
      const wishlistProducts = await pool.query(`
        SELECT p.id, p.name, p.price, p.image_url, p.category
        FROM products p
        INNER JOIN wishlist w ON p.id = w.product_id
        WHERE w.customer_id = $1 AND p.is_active = true
        AND p.id NOT IN (${recommendations.map(r => r.id).length > 0 ? recommendations.map(r => r.id).join(',') : 'NULL'})
        ORDER BY w.added_at DESC
        LIMIT $2
      `, [customerId, limit - recommendations.length]);
      
      recommendations = [...recommendations, ...wishlistProducts.rows];
    }
    
    // Strategy 3: Purchase history based recommendations
    if (recommendations.length < limit) {
      const purchaseHistory = await pool.query(`
        SELECT DISTINCT p.category, o.created_at
        FROM order_items oi
        INNER JOIN products p ON oi.product_id = p.id
        INNER JOIN orders o ON oi.order_id = o.id
        WHERE o.customer_id = $1 AND o.status != 'cancelled'
        ORDER BY o.created_at DESC
        LIMIT 3
      `, [customerId]);
      
      if (purchaseHistory.rows.length > 0) {
        const categories = purchaseHistory.rows.map(r => r.category);
        const categoryProducts = await pool.query(`
          SELECT p.id, p.name, p.price, p.image_url, p.category
          FROM products p
          WHERE p.category = ANY($1) AND p.is_active = true
          AND p.id NOT IN (${recommendations.map(r => r.id).length > 0 ? recommendations.map(r => r.id).join(',') : 'NULL'})
          ORDER BY p.created_at DESC
          LIMIT $2
        `, [categories, limit - recommendations.length]);
        
        recommendations = [...recommendations, ...categoryProducts.rows];
      }
    }
    
    // Strategy 4: Fallback to popular/trending products
    if (recommendations.length < limit) {
      const fallbackProducts = await pool.query(`
        SELECT p.id, p.name, p.price, p.image_url, p.category
        FROM products p
        WHERE p.is_active = true
        AND p.id NOT IN (${recommendations.map(r => r.id).length > 0 ? recommendations.map(r => r.id).join(',') : 'NULL'})
        ORDER BY p.created_at DESC
        LIMIT $2
      `, [limit - recommendations.length]);
      
      recommendations = [...recommendations, ...fallbackProducts.rows];
    }
    
    // Ensure we don't exceed the limit
    recommendations = recommendations.slice(0, limit);
    
    res.json({
      recommendations: recommendations,
      strategy: {
        recentlyViewed: recentlyViewed.length > 0,
        wishlist: recommendations.some(r => r.from_wishlist),
        purchaseHistory: recommendations.some(r => r.from_purchase_history),
        fallback: recommendations.some(r => r.from_fallback)
      }
    });
    
  } catch (error) {
    logger.error('Error getting recommendations:', error);
    // Fallback to random products if everything fails
    try {
      const fallbackProducts = await pool.query(`
        SELECT id, name, price, image_url, category
        FROM products 
        WHERE is_active = true
        ORDER BY RANDOM()
        LIMIT 4
      `);
      
      res.json({
        recommendations: fallbackProducts.rows,
        strategy: { fallback: true, error: 'Using fallback due to error' }
      });
    } catch (fallbackError) {
      res.status(500).json({ error: 'Failed to get recommendations' });
    }
  }
});

// Public Product Recommendations API (for non-logged-in users)
app.get('/api/recommendations/public', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const limit = parseInt(req.query.limit) || 4; // Default to 4 recommendations
    
    // For public users, show popular/trending products
    const popularProducts = await pool.query(`
      SELECT p.id, p.name, p.price, p.image_url, p.category
      FROM products p
      WHERE p.is_active = true
      ORDER BY p.created_at DESC
      LIMIT $1
    `, [limit]);
    
    res.json({
      recommendations: popularProducts.rows,
      strategy: { fallback: true, message: 'Showing popular products' }
    });
    
  } catch (error) {
    logger.error('Error getting public recommendations:', error);
    // Fallback to random products if everything fails
    try {
      const fallbackProducts = await pool.query(`
        SELECT id, name, price, image_url, category
        FROM products 
        WHERE is_active = true
        ORDER BY RANDOM()
        LIMIT 4
      `);
      
      res.json({
        recommendations: fallbackProducts.rows,
        strategy: { fallback: true, error: 'Using fallback due to error' }
      });
    } catch (fallbackError) {
      res.status(500).json({ error: 'Failed to get recommendations' });
    }
  }
});

// Set or clear a product's hero or featured feature (admin)
// Feature product validation
const validateFeatureProduct = [
  body('featured').isBoolean().withMessage('Featured must be a boolean value'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

app.put('/api/admin/products/:id/feature', authenticateToken, validateFeatureProduct, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Database not available' });
  const productId = req.params.id;
  const { in_hero, rank, in_featured, featured_order } = req.body || {};
  try {
    await pool.query('BEGIN');
    
    // Handle hero carousel updates
    if (in_hero !== undefined) {
      if (in_hero && [1,2,3].includes(Number(rank))) {
        // Clear any existing product at this rank
        await pool.query('UPDATE products SET feature_rank = NULL WHERE feature_rank = $1', [rank]);
        // Set this product's rank
        await pool.query('UPDATE products SET feature_rank = $1 WHERE id = $2', [rank, productId]);
      } else {
        // Clear hero flag for this product
        await pool.query('UPDATE products SET feature_rank = NULL WHERE id = $1', [productId]);
      }
    }
    
    // Handle featured collections updates
    if (in_featured !== undefined) {
      if (in_featured && [1,2,3,4,5,6].includes(Number(featured_order))) {
        // Clear any existing product at this position
        await pool.query('UPDATE products SET featured_order = NULL WHERE featured_order = $1', [featured_order]);
        // Set this product's position
        await pool.query('UPDATE products SET in_featured = true, featured_order = $1 WHERE id = $2', [featured_order, productId]);
      } else {
        // Clear featured flag for this product
        await pool.query('UPDATE products SET in_featured = false, featured_order = NULL WHERE id = $1', [productId]);
      }
    }
    
    await pool.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await pool.query('ROLLBACK');
    logger.error('Error updating product feature:', error);
    res.status(500).json({ error: 'Failed to update product feature' });
  }
});
// Search product by name
app.get('/api/products/search', async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const { name } = req.query;
    
    if (!name) {
      return res.status(400).json({ error: 'Product name is required' });
    }

    const result = await pool.query(`
      SELECT * FROM products WHERE name = $1
    `, [name]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    logger.error('Error searching product:', error);
    res.status(500).json({ error: 'Failed to search product' });
  }
});

// Image Upload Endpoint
app.post('/api/upload-image', authenticateToken, async (req, res) => {
  try {
    const { image, productName } = req.body;
    
    if (!image) {
      return res.status(400).json({ error: 'No image provided' });
    }
    
    // Upload to Cloudinary
    const cloudinaryUrl = await uploadImageToCloudinary(image, productName || 'admin-upload', 1, true);
    
    res.json({ url: cloudinaryUrl });
  } catch (error) {
    logger.error('Error uploading image:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

// Admin Product Management Endpoints
app.get('/api/admin/products', authenticateToken, async (req, res) => {
  if (!databaseAvailable) {
    logger.warn('⚠️ Database unavailable - returning mock products for testing');
    return res.json([
      {
        id: 1,
        name: "Test Product - Database Offline",
        description: "This is a mock product while database is unavailable",
        price: 25.00,
        category: "T-Shirts",
        colors: ["Black"],
        sizes: ["S", "M", "L", "XL", "2XL"],
        image_url: "https://via.placeholder.com/300x300/333/fff?text=Test+Product",
        size_chart: {
          S: { chest: "18", length: "28" },
          M: { chest: "20", length: "29" },
          L: { chest: "22", length: "30" },
          XL: { chest: "24", length: "31" },
          "2XL": { chest: "26", length: "32" }
        },
        is_active: true,
        created_at: new Date().toISOString()
      }
    ]);
  }

  try {
    const result = await pool.query(`
      SELECT * FROM products WHERE is_active = true ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    logger.error('Error fetching products:', error);
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// Get single product by ID
app.get('/api/admin/products/:id', authenticateToken, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const productId = req.params.id;
    const result = await pool.query(`
      SELECT * FROM products WHERE id = $1 AND is_active = true
    `, [productId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const product = result.rows[0];
    
    // Debug logging removed to prevent Railway rate limit issues

    res.json(product);
  } catch (error) {
    logger.error('Error fetching product:', error);
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// Product validation middleware
const validateProduct = [
  body('name').notEmpty().trim().withMessage('Product name is required'),
  body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
  body('category').notEmpty().trim().withMessage('Category is required'),
  body('description').optional().isString().withMessage('Description must be a string'),
  body('stock_quantity').optional().isInt({ min: 0 }).withMessage('Stock quantity must be a non-negative integer'),
  body('sale_percentage').optional().isFloat({ min: 0, max: 100 }).withMessage('Sale percentage must be between 0 and 100'),
  body('tags').optional().isArray().withMessage('Tags must be an array'),
  body('colors').optional().isArray().withMessage('Colors must be an array'),
  body('sizes').optional().isArray().withMessage('Sizes must be an array'),
  body('custom_birthday_enabled').optional().isBoolean().withMessage('Custom birthday enabled must be a boolean'),
  body('custom_birthday_required').optional().isBoolean().withMessage('Custom birthday required must be a boolean'),
  body('custom_birthday_fields').optional().custom((value) => {
    // Accept both arrays and JSON strings
    if (Array.isArray(value)) return true;
    if (typeof value === 'string') {
      try { JSON.parse(value); return true; } catch { return false; }
    }
    return false;
  }).withMessage('Custom birthday fields must be an array or valid JSON string'),
  body('custom_birthday_labels').optional().custom((value) => {
    // Accept both objects and JSON strings
    if (typeof value === 'object' && value !== null) return true;
    if (typeof value === 'string') {
      try { JSON.parse(value); return true; } catch { return false; }
    }
    return false;
  }).withMessage('Custom birthday labels must be an object or valid JSON string'),
  body('custom_birthday_char_limit').optional().isInt({ min: 50, max: 1000 }).withMessage('Custom birthday character limit must be between 50 and 1000'),
  body('custom_birthday_question').optional().isString().isLength({ max: 500 }).withMessage('Custom birthday question must be less than 500 characters'),
  body('custom_lyrics_enabled').optional().isBoolean().withMessage('Custom lyrics enabled must be a boolean'),
  body('custom_lyrics_required').optional().isBoolean().withMessage('Custom lyrics required must be a boolean'),
  body('custom_lyrics_fields').optional().custom((value) => {
    // Accept both arrays and JSON strings
    if (Array.isArray(value)) return true;
    if (typeof value === 'string') {
      try { JSON.parse(value); return true; } catch { return false; }
    }
    return false;
  }).withMessage('Custom lyrics fields must be an array or valid JSON string'),
  body('custom_lyrics_labels').optional().custom((value) => {
    // Accept both objects and JSON strings
    if (typeof value === 'object' && value !== null) return true;
    if (typeof value === 'string') {
      try { JSON.parse(value); return true; } catch { return false; }
    }
    return false;
  }).withMessage('Custom lyrics labels must be an object or valid JSON string'),
  body('custom_lyrics_char_limit').optional().isInt({ min: 50, max: 1000 }).withMessage('Custom lyrics character limit must be between 50 and 1000'),
  body('custom_lyrics_question').optional().isString().isLength({ max: 500 }).withMessage('Custom lyrics question must be less than 500 characters'),
  body('specifications.brand_preference').optional().isString().withMessage('Brand preference must be a string'),
  body('shipping_cost').optional().isFloat({ min: 0 }).withMessage('Shipping cost must be a positive number'),
  body('additional_item_shipping').optional().custom((value) => {
    if (value === null || value === undefined || value === '') return true;
    const num = parseFloat(value);
    if (isNaN(num) || num < 0) {
      throw new Error('Additional item shipping must be a positive number or null');
    }
    return true;
  }),
  body('local_pickup_enabled').optional().isBoolean().withMessage('Local pickup enabled must be a boolean'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.debug('🔍 Validation errors:', JSON.stringify(errors.array(), null, 2));
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

app.post('/api/admin/products', authenticateToken, validateProduct, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const {
      name,
      description,
      price,
      original_price,
      category,
      stock_quantity,
      low_stock_threshold,
      sale_percentage,
      tags,
      colors,
      sizes,
      images,
      specifications,
      features,
      custom_birthday_enabled,
      custom_birthday_required,
      custom_birthday_fields,
      custom_birthday_labels,
      custom_birthday_char_limit,
      custom_birthday_question,
      custom_lyrics_enabled,
      custom_lyrics_required,
      custom_lyrics_fields,
      custom_lyrics_labels,
      custom_lyrics_char_limit,
      custom_lyrics_question,
      shipping_cost,
      additional_item_shipping,
      local_pickup_enabled,
      size_chart,
      size_chart_enabled,
      color_chart_enabled
    } = req.body;

    // Process tags to ensure it's always a JavaScript array
    let processedTags = [];
    if (Array.isArray(tags)) {
      processedTags = tags;
    } else if (typeof tags === 'string') {
      // Try to parse as JSON first (in case it's a JSON string)
      try {
        const parsedTags = JSON.parse(tags);
        if (Array.isArray(parsedTags)) {
          processedTags = parsedTags;
        } else {
          // If not an array, treat as comma-separated string
          processedTags = tags.split(',').map(tag => tag.trim()).filter(tag => tag !== '');
        }
      } catch (e) {
        // If JSON parsing fails, treat as comma-separated string
        processedTags = tags.split(',').map(tag => tag.trim()).filter(tag => tag !== '');
      }
    }

    // Get the next sequential ID
    const nextIdResult = await pool.query(`
      SELECT COALESCE(MAX(id), 0) + 1 as next_id FROM products
    `);
    const nextId = nextIdResult.rows[0].next_id;

    // Handle image uploads to Cloudinary
    let image_url = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgdmlld0JveD0iMCAwIDEwMCAxMDAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSIjM0I0QjVCIi8+CjxwYXRoIGQ9Ik0yNSAyNUg3NVY3NUgyNVoiIHN0cm9rZT0iIzAwQkNENCIgc3Ryb2tlLXdpZHRoPSIyIiBmaWxsPSJub25lIi8+CjxwYXRoIGQ9Ik0zNSA0NUw2NSA0NU02NSA2NUwzNSA2NUwzNSA0NVoiIHN0cm9rZT0iIzAwQkNENCIgc3Ryb2tlLXdpZHRoPSIyIiBmaWxsPSJub25lIi8+Cjwvc3ZnPgo=';
    let sub_images = [];
    
    logger.info('🔍 DEBUG: Received images data:', JSON.stringify(images, null, 2));
    
    if (images && images.length > 0) {
      try {
        logger.info(`☁️ Uploading ${images.length} images to Cloudinary for product: ${name}`);
        logger.info('�� DEBUG: First image structure:', JSON.stringify(images[0], null, 2));
        
        // Upload images to Cloudinary
        const uploadedUrls = await uploadProductImages(images, name);
        
        if (uploadedUrls.mainImage) {
          image_url = uploadedUrls.mainImage;
          logger.info(`✅ Main image uploaded to Cloudinary: ${image_url}`);
        }
        
        if (uploadedUrls.subImages.length > 0) {
          sub_images = uploadedUrls.subImages;
          logger.info(`✅ ${sub_images.length} sub images uploaded to Cloudinary`);
        }
        
        logger.info(`🎉 All images uploaded successfully to Cloudinary for product: ${name}`);
      } catch (imageError) {
        logger.error('❌ Error uploading images to Cloudinary:', imageError);
        // Continue without images if there's an error
        logger.info('⚠️ Continuing product creation without images');
      }
    } else {
      logger.info('⚠️ No images provided for upload');
    }

    // Insert product with sequential ID
    logger.info(`💾 Inserting product into database: ID ${nextId}, Name: ${name}`);
    
    // Collect size stock quantities from the request (sanitize: remove XS)
    const sizeStockRaw = req.body.size_stock || {};
    const sizeStock = Object.fromEntries(Object.entries(sizeStockRaw).filter(([k]) => k !== 'XS'));
    // Sanitize sizes: ensure array and drop XS
    const sizesArray = Array.isArray(sizes) ? sizes : [];
    const sizesFiltered = sizesArray.filter(s => s !== 'XS');
    
    const result = await pool.query(`
      INSERT INTO products (
        id, name, description, price, image_url, category, stock_quantity, low_stock_threshold, 
        is_active, created_at, updated_at, is_featured, original_price, subcategory, tags, 
        is_on_sale, sale_percentage, colors, sizes, specifications, features, sub_images, 
        size_stock, track_inventory, brand_preference, specs_notes, feature_rank, in_featured, 
        featured_order, size_pricing, custom_birthday_enabled, custom_birthday_required, 
        custom_birthday_fields, custom_birthday_labels, custom_birthday_char_limit, 
        custom_lyrics_enabled, custom_lyrics_required, custom_lyrics_fields, custom_lyrics_labels, 
        custom_lyrics_char_limit, shipping_cost, additional_item_shipping, local_pickup_enabled, size_chart, 
        custom_birthday_question, custom_lyrics_question, size_chart_enabled, color_chart_enabled
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48)
      RETURNING *
    `, [
      nextId, // id
      name, // name
      description, // description
      price, // price
      image_url, // image_url
      category, // category
      stock_quantity || 50, // stock_quantity
      low_stock_threshold || 5, // low_stock_threshold
      true, // is_active
      new Date(), // created_at
      new Date(), // updated_at
      true, // is_featured
      original_price, // original_price
      'Featured', // subcategory
      processedTags, // tags
      true, // is_on_sale
      sale_percentage || 15, // sale_percentage
      JSON.stringify(colors || []), // colors
      JSON.stringify(sizesFiltered), // sizes
      JSON.stringify(specifications || {}), // specifications
      JSON.stringify(features || {}), // features
      JSON.stringify(sub_images), // sub_images
      JSON.stringify(sizeStock), // size_stock
      !!req.body.track_inventory, // track_inventory
      (specifications && specifications.brand_preference) || 'Either (Gildan Softstyle 64000 or Bella+Canvas 3001)', // brand_preference
      req.body.specs_notes || '', // specs_notes
      null, // feature_rank
      false, // in_featured
      null, // featured_order
      JSON.stringify({}), // size_pricing
      custom_birthday_enabled || false, // custom_birthday_enabled
      custom_birthday_required || false, // custom_birthday_required
      custom_birthday_fields || '["birthdate", "name", "additional_info"]', // custom_birthday_fields
      custom_birthday_labels || '{"birthdate": "Birthdate", "name": "Name", "additional_info": "Any other references or information"}', // custom_birthday_labels
      custom_birthday_char_limit || 250, // custom_birthday_char_limit
      custom_lyrics_enabled || false, // custom_lyrics_enabled
      custom_lyrics_required || false, // custom_lyrics_required
      custom_lyrics_fields || '["artist_band", "song_name", "song_lyrics"]', // custom_lyrics_fields
      custom_lyrics_labels || '{"artist_band": "Artist or Band Name", "song_name": "Song Name", "song_lyrics": "Song Lyrics (Optional)"}', // custom_lyrics_labels
      custom_lyrics_char_limit || 250, // custom_lyrics_char_limit
      shipping_cost || 4.50, // shipping_cost
      req.body.additional_item_shipping || null, // additional_item_shipping (null uses env default)
      local_pickup_enabled !== false, // local_pickup_enabled
      JSON.stringify(size_chart || { // size_chart
        S: { chest: '18', length: '28' },
        M: { chest: '20', length: '29' },
        L: { chest: '22', length: '30' },
        XL: { chest: '24', length: '31' },
        '2XL': { chest: '26', length: '32' }
      }),
      custom_birthday_question || '', // custom_birthday_question
      custom_lyrics_question || '', // custom_lyrics_question
      size_chart_enabled !== false, // size_chart_enabled
      color_chart_enabled !== false // color_chart_enabled
    ]);

    logger.info(`✅ Product created with ID ${nextId}`);

    // Create edit page for the new product
    try {
      const { createEditPageForProduct } = require('./create_edit_page_for_product.js');
      const editPageCreated = createEditPageForProduct(nextId, name);
      
      if (editPageCreated) {
        logger.info(`✅ Edit page created for product ${nextId}`);
      } else {
        logger.info(`⚠️ Failed to create edit page for product ${nextId}`);
      }
    } catch (editPageError) {
      logger.error('❌ Error creating edit page:', editPageError);
      logger.info('⚠️ Continuing without edit page creation');
    }

    // Optionally generate static product page (feature-flagged)
    if (FEATURE_STATIC_PRODUCT_PAGES) {
      try {
        const { buildStaticProductPage } = require('./tools/static_product_builder');
        await buildStaticProductPage(result.rows[0]);
        logger.info(`🧱 Static product page generated for ID ${nextId}`);
      } catch (e) {
        logger.error('❌ Static page build failed:', e.message || e);
      }
    }

    res.json({ message: 'Product created successfully', product: result.rows[0] });
  } catch (error) {
    logger.error('Error creating product:', error);
    res.status(500).json({ error: 'Failed to create product' });
  }
});
app.put('/api/admin/products/:id', authenticateToken, validateProduct, async (req, res) => {
  logger.info('🔍 [DEBUG] PUT endpoint called for product ID:', req.params.id);
  logger.info('🔍 [DEBUG] Request body received:', req.body);
  logger.info('🔍 [DEBUG] Starting product update process...');
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const productId = req.params.id;
    
    // Debug: Log the incoming request body
    logger.info('🔍 Admin product update - Request body:', JSON.stringify(req.body, null, 2));
    
    const {
      name,
      description,
      price,
      original_price,
      category,
      stock_quantity,
      low_stock_threshold,
      sale_percentage,
      tags,
      colors,
      sizes,
      size_stock,
      images,
      image_url,
      sub_images,
      specifications,
      features,
      custom_birthday_enabled,
      custom_birthday_required,
      custom_birthday_fields,
      custom_birthday_labels,
      custom_birthday_char_limit,
      custom_birthday_question,
      custom_lyrics_enabled,
      custom_lyrics_required,
      custom_lyrics_fields,
      custom_lyrics_labels,
      custom_lyrics_char_limit,
      custom_lyrics_question,
      shipping_cost,
      additional_item_shipping,
      local_pickup_enabled,
      size_chart,
      size_chart_enabled,
      color_chart_enabled
    } = req.body;
    
    // Debug: Log the extracted custom input values
    logger.info('🔍 Custom input values extracted:', {
      custom_birthday_question,
      custom_lyrics_enabled,
      custom_lyrics_required,
      custom_lyrics_fields,
      custom_lyrics_labels,
      custom_lyrics_char_limit,
      custom_lyrics_question
    });

    // Process tags to ensure it's always a JavaScript array
    let processedTags = [];
    if (Array.isArray(tags)) {
      processedTags = tags;
    } else if (typeof tags === 'string') {
      // Try to parse as JSON first (in case it's a JSON string)
      try {
        const parsedTags = JSON.parse(tags);
        if (Array.isArray(parsedTags)) {
          processedTags = parsedTags;
        } else {
          // If not an array, treat as comma-separated string
          processedTags = tags.split(',').map(tag => tag.trim()).filter(tag => tag !== '');
        }
      } catch (e) {
        // If JSON parsing fails, treat as comma-separated string
        processedTags = tags.split(',').map(tag => tag.trim()).filter(tag => tag !== '');
      }
    }

    // Validate required fields
    if (!name || !price) {
      return res.status(400).json({ error: 'Name and price are required' });
    }
    
    // If category is empty, use a default value
    const finalCategory = category || 'Uncategorized';

    // Handle image uploads to Cloudinary
    let final_image_url = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTAwIiBoZWlnaHQ9IjEwMCIgdmlld0JveD0iMCAwIDEwMCAxMDAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxMDAiIGhlaWdodD0iMTAwIiBmaWxsPSIjM0I0QjVCIi8+CjxwYXRoIGQ9Ik0yNSAyNUg3NVY3NUgyNVoiIHN0cm9rZT0iIzAwQkNENCIgc3Ryb2tlLXdpZHRoPSIyIiBmaWxsPSJub25lIi8+CjxwYXRoIGQ9Ik0zNSA0NUw2NSA0NU02NSA2NUwzNSA2NUwzNSA0NVoiIHN0cm9rZT0iIzAwQkNENCIgc3Ryb2tlLXdpZHRoPSIyIiBmaWxsPSJub25lIi8+Cjwvc3ZnPgo=';
    let final_sub_images = [];
    
    // Handle images from client. Supports three cases:
    // 1) images: array of objects { data } (legacy create flow)
    // 2) images: array of strings: either data URLs (base64) or http(s) URLs (mixed)
    // 3) image_url + sub_images: keep existing URLs
    let processedMixedImages = null; // when provided via 'images'

    if (Array.isArray(images) && images.length > 0) {
      logger.info(`📸 Received ${images.length} images from client for processing`);
      logger.info(`🔍 DEBUG: First image structure:`, JSON.stringify(images[0], null, 2));
      processedMixedImages = [];

      for (let i = 0; i < Math.min(images.length, 5); i += 1) {
        const item = images[i];
        logger.info(`🔍 DEBUG: Processing image ${i + 1}:`, typeof item, item ? (typeof item === 'object' ? Object.keys(item) : 'string') : 'null');
        try {
          // Case A: object with .data (base64)
          if (item && typeof item === 'object' && typeof item.data === 'string') {
            const url = await uploadImageToCloudinary(item.data, name, i + 1, i === 0);
            processedMixedImages.push(url);
            logger.info(`✅ Uploaded image ${i + 1} as ${i === 0 ? 'MAIN' : 'SUB'}: ${url}`);
            continue;
          }
          // Case B: string data URL (base64) → upload
          if (typeof item === 'string' && item.startsWith('data:')) {
            const url = await uploadImageToCloudinary(item, name, i + 1, i === 0);
            processedMixedImages.push(url);
            logger.info(`✅ Uploaded image ${i + 1} as ${i === 0 ? 'MAIN' : 'SUB'}: ${url}`);
            continue;
          }
          // Case C: string http(s) URL → keep as-is
          if (typeof item === 'string' && /^https?:\/\//i.test(item)) {
            processedMixedImages.push(item);
            logger.info(`✅ Kept existing image ${i + 1} as ${i === 0 ? 'MAIN' : 'SUB'}: ${item}`);
            continue;
          }
        } catch (uErr) {
          logger.error(`❌ Failed processing image index ${i}:`, uErr?.message || uErr);
        }
      }

      // Apply processed images if at least one valid
      if (processedMixedImages.length > 0) {
        // Ensure the first image is always the main image
        final_image_url = processedMixedImages[0] || final_image_url;
        final_sub_images = processedMixedImages.slice(1);
        logger.info(`✅ Final images prepared from mixed payload. main=${final_image_url}, subs=${final_sub_images.length}`);
        logger.info(`🔍 DEBUG: processedMixedImages array:`, processedMixedImages);
      } else {
        logger.warn('⚠️ No valid images processed from payload; retaining existing image_url/sub_images');
      }
    } else if (image_url || (sub_images && sub_images.length > 0)) {
      // Existing images (URL format) - keep them as is
      if (image_url && !image_url.startsWith('data:')) {
        final_image_url = image_url;
        logger.info(`✅ Keeping existing main image: ${final_image_url}`);
      }
      if (sub_images && Array.isArray(sub_images)) {
        final_sub_images = sub_images.filter(img => img && !img.startsWith('data:'));
        logger.info(`✅ Keeping ${final_sub_images.length} existing sub images`);
      }
    }

    // Debug what we're receiving
    logger.info('🔍 Server received brand_preference:', req.body.brand_preference);
    logger.info('🔍 Server received specifications:', req.body.specifications);
    
    // Ensure specifications include standard care instructions for all printed apparel
    const defaultSpecifications = {
      material: '100% Premium Cotton',
      weight: '180 GSM',
      fit: 'Unisex Regular',
      neck_style: 'Crew Neck',
      sleeve_length: 'Short Sleeve',
      origin: 'Made in USA',
      print_method: 'Direct-to-Garment',
      sustainability: 'Eco-Friendly Inks',
      care_instructions: {
        machine_wash_cold: true,
        turn_inside_out: true,
        mild_detergent: true,
        no_fabric_softener: true,
        no_bleach: true,
        no_dry_clean_iron: true
      }
    };
    
    // Merge user specifications with defaults, ensuring care instructions are always included
    const finalSpecifications = {
      ...defaultSpecifications,
      ...(specifications || {}),
      care_instructions: {
        ...defaultSpecifications.care_instructions,
        ...(specifications?.care_instructions || {})
      }
    };
    
    // Update product
    logger.info('🔍 About to execute UPDATE query with brand_preference:', req.body.brand_preference);
    
    // Add detailed debugging for the UPDATE execution
    logger.info('🔍 [DEBUG] About to execute UPDATE for product ID:', productId);
    logger.info('🔍 [DEBUG] brand_preference value being sent:', req.body.brand_preference);
    
    const result = await pool.query(`
      UPDATE products SET
        name = $1, description = $2, price = $3, original_price = $4, 
        image_url = $5, category = $6, tags = $7, stock_quantity = $8,
        low_stock_threshold = $9, sale_percentage = $10, colors = $11,
        sizes = $12, specifications = $13, features = $14, sub_images = $15,
        size_stock = $16, track_inventory = $17, brand_preference = $18, specs_notes = $19,
        custom_birthday_enabled = $20, custom_birthday_required = $21, custom_birthday_fields = $22, custom_birthday_labels = $23, custom_birthday_char_limit = $24, custom_birthday_question = $25,
        custom_lyrics_enabled = $26, custom_lyrics_required = $27, custom_lyrics_fields = $28, custom_lyrics_labels = $29, custom_lyrics_char_limit = $30, custom_lyrics_question = $31,
        shipping_cost = $32, additional_item_shipping = $33, local_pickup_enabled = $34, size_chart = $35, size_chart_enabled = $36, color_chart_enabled = $37,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $38
      RETURNING *
    `, [
      name, description, price, original_price, final_image_url, finalCategory,
      processedTags, stock_quantity || 50, low_stock_threshold || 5,
      sale_percentage || 15, JSON.stringify(colors || []), JSON.stringify((Array.isArray(sizes) ? sizes.filter(s => s !== 'XS') : [])),
      JSON.stringify(finalSpecifications), JSON.stringify(features || {}),
      JSON.stringify(final_sub_images), JSON.stringify(size_stock || {}),
      !!req.body.track_inventory, (finalSpecifications && finalSpecifications.brand_preference) || 'Either (Gildan Softstyle 64000 or Bella+Canvas 3001)', req.body.specs_notes || '',
      custom_birthday_enabled || false, custom_birthday_required || false, 
      custom_birthday_fields || '["birthdate", "name", "additional_info"]',
      custom_birthday_labels || '{"birthdate": "Birthdate", "name": "Name", "additional_info": "Any other references or information"}',
      custom_birthday_char_limit || 250,
      custom_birthday_question || '',
      custom_lyrics_enabled || false, custom_lyrics_required || false,
      custom_lyrics_fields || '["artist_band", "song_name", "song_lyrics"]',
      custom_lyrics_labels || '{"artist_band": "Artist or Band Name", "song_name": "Song Name", "song_lyrics": "Song Lyrics (Optional)"}',
      custom_lyrics_char_limit || 250,
      custom_lyrics_question || '',
      shipping_cost || 4.50, 
      additional_item_shipping || null, // null uses env default
      local_pickup_enabled !== false,
      JSON.stringify(size_chart || {
        S: { chest: '18', length: '28' },
        M: { chest: '20', length: '29' },
        L: { chest: '22', length: '30' },
        XL: { chest: '24', length: '31' },
        '2XL': { chest: '26', length: '32' }
      }),
      size_chart_enabled !== false, // size_chart_enabled
      color_chart_enabled !== false, // color_chart_enabled
      productId
    ]);

    // Debug what was actually updated
    logger.info('🔍 [DEBUG] UPDATE result:', result);
    logger.info('🔍 [DEBUG] Rows affected:', result.rowCount);
    logger.info('🔍 Database UPDATE result - brand_preference field:', result.rows[0].brand_preference);
    logger.info('🔍 Database UPDATE result - specifications:', result.rows[0].specifications);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    // Update edit page if product name changed
    try {
      const { createEditPageForProduct } = require('./create_edit_page_for_product.js');
      const editPageCreated = createEditPageForProduct(productId, name);
      
      if (editPageCreated) {
        logger.info(`✅ Edit page updated for product ${productId} with new name: ${name}`);
      } else {
        logger.info(`⚠️ Failed to update edit page for product ${productId}`);
      }
    } catch (editPageError) {
      logger.error('❌ Error updating edit page:', editPageError);
      logger.info('⚠️ Continuing without edit page update');
    }

    // Optionally regenerate static product page (feature-flagged)
    if (FEATURE_STATIC_PRODUCT_PAGES) {
      try {
        const { buildStaticProductPage } = require('./tools/static_product_builder');
        await buildStaticProductPage(result.rows[0]);
        logger.info(`🧱 Static product page regenerated for ID ${productId}`);
      } catch (e) {
        logger.error('❌ Static page rebuild failed:', e.message || e);
      }
    }

    res.json({ message: 'Product updated successfully', product: result.rows[0] });
  } catch (error) {
    logger.error('Error updating product:', error);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

app.delete('/api/admin/products/:id', authenticateToken, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const productId = req.params.id;

    // Check if product exists and get image URLs
    const checkResult = await pool.query(`
      SELECT id, image_url, sub_images FROM products WHERE id = $1
    `, [productId]);

    if (checkResult.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }

    const product = checkResult.rows[0];
    
    // Collect all image URLs for deletion from Cloudinary
    const imageUrlsToDelete = [];
    if (product.image_url && !product.image_url.startsWith('data:')) {
      imageUrlsToDelete.push(product.image_url);
    }
    
    if (product.sub_images && Array.isArray(product.sub_images)) {
      product.sub_images.forEach(url => {
        if (url && !url.startsWith('data:')) {
          imageUrlsToDelete.push(url);
        }
      });
    }
    
    // Delete images from Cloudinary
    if (imageUrlsToDelete.length > 0) {
      try {
        await deleteImagesFromCloudinary(imageUrlsToDelete);
        logger.info(`✅ Deleted ${imageUrlsToDelete.length} images from Cloudinary`);
      } catch (error) {
        logger.error('❌ Error deleting images from Cloudinary:', error);
      }
    }

    // Soft-delete: mark product inactive to preserve order history
    await pool.query(`
      UPDATE products SET is_active = false, updated_at = CURRENT_TIMESTAMP WHERE id = $1
    `, [productId]);

    logger.info(`✅ Product ${productId} archived (soft-deleted) successfully`);

    // Delete edit page for the product
    const editPagePattern = `product-edit-product-${productId}_*.html`;
    const pagesDir = path.join(__dirname, 'pages');
    
    try {
      const files = fs.readdirSync(pagesDir);
      const editPageFile = files.find(file => file.startsWith(`product-edit-product-${productId}_`));
      
      if (editPageFile) {
        const editPagePath = path.join(pagesDir, editPageFile);
        fs.unlinkSync(editPagePath);
        logger.info(`✅ Deleted edit page: ${editPageFile}`);
      }
    } catch (error) {
      logger.info(`⚠️ Error deleting edit page for product ${productId}:`, error.message);
    }

    res.json({ message: 'Product archived successfully' });
  } catch (error) {
    logger.error('Error deleting product:', error);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

// Checkout validation middleware
const validateCheckout = [
  body('shipping_address').notEmpty().trim().withMessage('Shipping address is required'),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

// Checkout - convert cart to order
app.post('/api/cart/checkout', authenticateCustomer, validateCheckout, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const customerId = req.customer.id;
    const { shipping_address } = req.body;

    // Get customer info
    const customerResult = await pool.query(`
      SELECT id, email, first_name, last_name FROM customers WHERE id = $1
    `, [customerId]);

    if (customerResult.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    const customer = customerResult.rows[0];

    // Get cart items from cart table
    const cartResult = await pool.query(`
      SELECT * FROM cart WHERE customer_id = $1
    `, [customerId]);

    if (cartResult.rows.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    const cartItems = cartResult.rows;
    const total_amount = cartItems.reduce((sum, item) => sum + (item.quantity * parseFloat(item.unit_price)), 0);

    // Generate order number
    const orderNumber = 'PLW-' + new Date().getFullYear() + '-' + String(Date.now()).slice(-4);

    // Create order
    const orderResult = await pool.query(`
            INSERT INTO orders (order_number, customer_id, customer_email, customer_name, total_amount, shipping_address, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'pending')
      RETURNING *
    `, [orderNumber, customerId, customer.email, `${customer.first_name} ${customer.last_name}`, total_amount, shipping_address]);

    const order = orderResult.rows[0];

    // Create order items from cart items
    for (const item of cartItems) {
      await pool.query(`
        INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price, size, color, custom_input)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [order.id, item.product_id, item.product_name, item.quantity, item.unit_price, (item.quantity * item.unit_price), item.size, item.color, item.custom_input]);
    }

    // Clear cart after successful order
    await pool.query(`
      DELETE FROM cart WHERE customer_id = $1
    `, [customerId]);

    // Update customer stats
    await pool.query(`
      UPDATE customers 
      SET total_orders = total_orders + 1,
          total_spent = total_spent + $1,
          average_order_value = (total_spent + $1) / (total_orders + 1),
          loyalty_points = loyalty_points + FLOOR($1 * 0.1)
      WHERE id = $2
    `, [total_amount, customerId]);

    res.json({ 
      message: 'Order created successfully', 
      order: order,
      orderNumber: orderNumber
    });
  } catch (error) {
    logger.error('Error during checkout:', error);
    res.status(500).json({ error: 'Failed to process checkout' });
  }
});

// ========================================
// PAYPAL PAYMENT API ENDPOINTS
// ========================================

// Get PayPal Client ID (for frontend)
app.get('/api/paypal/client-id', (req, res) => {
  if (!paypalClientId) {
    logger.error('❌ PayPal Client ID not configured');
    return res.status(500).json({ error: 'PayPal not configured' });
  }
  res.json({ clientId: paypalClientId });
});

// Create PayPal order
app.post('/api/paypal/create-order', authenticateCustomer, async (req, res) => {
  if (!paypalClient) {
    return res.status(500).json({ error: 'PayPal not configured' });
  }

  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const customerId = req.customer.id;
    const { shipping_address } = req.body;

    // Get customer info
    const customerResult = await pool.query(`
      SELECT id, email, first_name, last_name FROM customers WHERE id = $1
    `, [customerId]);

    if (customerResult.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    const customer = customerResult.rows[0];

    // Get cart items
    const cartResult = await pool.query(`
      SELECT * FROM cart WHERE customer_id = $1
    `, [customerId]);

    if (cartResult.rows.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    const cartItems = cartResult.rows;
    const subtotal = cartItems.reduce((sum, item) => sum + (item.quantity * parseFloat(item.unit_price)), 0);
    const shipping = await calculateTieredShipping(cartItems);
    const tax = subtotal * 0.085; // 8.5% tax
    const total = subtotal + shipping + tax;

    // Generate order number
    const orderNumber = 'PLW-' + new Date().getFullYear() + '-' + String(Date.now()).slice(-4);

    // Create order in database first (with pending status)
    const orderResult = await pool.query(`
            INSERT INTO orders (order_number, customer_id, customer_email, customer_name, total_amount, shipping_address, payment_method, payment_status, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
      RETURNING *
    `, [
      orderNumber, 
      customerId, 
      customer.email, 
      `${customer.first_name} ${customer.last_name}`,
      total,
      JSON.stringify(shipping_address),
      'paypal',
      'pending'
    ]);

    const order = orderResult.rows[0];

    // Create order items
    for (const item of cartItems) {
      await pool.query(`
        INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price, size, color, custom_input)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        order.id, 
        item.product_id, 
        item.product_name, 
        item.quantity, 
        item.unit_price, 
        (item.quantity * parseFloat(item.unit_price)), 
        item.size, 
        item.color, 
        item.custom_input
      ]);
    }

    // Create PayPal order with our order ID as custom_id
    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: 'CAPTURE',
      purchase_units: [{
        custom_id: order.id.toString(), // This is crucial for webhook identification
        amount: {
          currency_code: 'USD',
          value: total.toFixed(2),
          breakdown: {
            item_total: {
              currency_code: 'USD',
              value: subtotal.toFixed(2)
            },
            shipping: {
              currency_code: 'USD',
              value: shipping.toFixed(2)
            },
            tax_total: {
              currency_code: 'USD',
              value: tax.toFixed(2)
            }
          }
        },
        items: cartItems.map(item => ({
          name: item.product_name,
          unit_amount: {
            currency_code: 'USD',
            value: parseFloat(item.unit_price).toFixed(2)
          },
          quantity: item.quantity.toString(),
          category: 'PHYSICAL_GOODS'
        })),
        shipping: {
          name: {
            full_name: `${shipping_address.first_name} ${shipping_address.last_name}`
          },
          address: {
            address_line_1: shipping_address.address,
            admin_area_2: shipping_address.city,
            admin_area_1: shipping_address.state,
            postal_code: shipping_address.zip,
            country_code: 'US'
          }
        }
      }]
    });

    const response = await paypalClient.execute(request);
    
    // Store PayPal Order ID in payment_id for webhook matching
    await pool.query(`
      UPDATE orders SET payment_id = $1 WHERE id = $2
    `, [response.result.id, order.id]);
    
    logger.info('🔍 Order created with PayPal ID:', response.result.id);
    logger.info('🔍 Database order ID:', order.id);
    logger.info('🔍 Order number:', orderNumber);

    res.json({ 
      id: response.result.id,
      orderNumber: orderNumber,
      total: total
    });
  } catch (error) {
    console.error('PayPal create order error:', error);
    logger.error('PayPal create order error:', error);
    res.status(500).json({ error: 'Failed to create PayPal order', details: error.message });
  }
});

// Capture PayPal order
app.post('/api/paypal/capture-order', authenticateCustomer, async (req, res) => {
  if (!paypalClient) {
    return res.status(500).json({ error: 'PayPal not configured' });
  }

  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const { orderId } = req.body;
    const customerId = req.customer.id;

    // Capture the order
    const request = new paypal.orders.OrdersCaptureRequest(orderId);
    request.requestBody({});
    const response = await paypalClient.execute(request);

    if (response.result.status === 'COMPLETED') {
      // Find the order by PayPal order ID
      const orderResult = await pool.query(`
        SELECT * FROM orders WHERE payment_id = $1
      `, [orderId]);

      if (orderResult.rows.length === 0) {
        return res.status(404).json({ error: 'Order not found' });
      }

      const order = orderResult.rows[0];

      // Update order status to pending (not completed)
      await pool.query(`
        UPDATE orders 
        SET status = 'pending',
            payment_status = 'completed', 
            payment_details = $1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
      `, [JSON.stringify(response.result), order.id]);

      // Clear cart
      await pool.query(`
        DELETE FROM cart WHERE customer_id = $1
      `, [customerId]);

      // Update customer stats
      await pool.query(`
        UPDATE customers 
        SET total_orders = total_orders + 1,
            total_spent = total_spent + $1,
            average_order_value = (total_spent + $1) / (total_orders + 1),
            loyalty_points = loyalty_points + FLOOR($1 * 0.1)
        WHERE id = $2
      `, [order.total_amount, customerId]);

      res.json({ 
        message: 'Payment captured successfully', 
        order: order,
        orderNumber: order.order_number,
        finalTotal: order.total_amount,
        paymentDetails: response.result
      });
    } else {
      res.status(400).json({ error: 'Payment not completed' });
    }
  } catch (error) {
    logger.error('PayPal capture order error:', error);
    res.status(500).json({ error: 'Failed to capture PayPal order' });
  }
});

// Create order with payment details (for checkout page)
app.post('/api/orders/create', authenticateCustomer, async (req, res) => {
  if (!pool) {
    return res.status(500).json({ error: 'Database not available' });
  }

  try {
    const customerId = req.customer.id;
    const { shipping_address, payment_method, payment_id, payment_details } = req.body;

    // Get customer info
    const customerResult = await pool.query(`
      SELECT id, email, first_name, last_name FROM customers WHERE id = $1
    `, [customerId]);

    if (customerResult.rows.length === 0) {
      return res.status(404).json({ error: 'Customer not found' });
    }

    const customer = customerResult.rows[0];

    // Get cart items
    const cartResult = await pool.query(`
      SELECT * FROM cart WHERE customer_id = $1
    `, [customerId]);

    if (cartResult.rows.length === 0) {
      return res.status(400).json({ error: 'Cart is empty' });
    }

    const cartItems = cartResult.rows;
    const total_amount = cartItems.reduce((sum, item) => sum + (item.quantity * parseFloat(item.unit_price)), 0);

    // Generate order number
    const orderNumber = 'PLW-' + new Date().getFullYear() + '-' + String(Date.now()).slice(-4);

    // Create order
    const orderResult = await pool.query(`
            INSERT INTO orders (order_number, customer_id, customer_email, customer_name, total_amount, shipping_address, payment_method, payment_id, payment_status, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending')
      RETURNING *
    `, [
      orderNumber, 
      customerId, 
      customer.email, 
      `${customer.first_name} ${customer.last_name}`, 
      total_amount, 
      JSON.stringify(shipping_address),
      payment_method || 'paypal',
      payment_id,
      'completed'
    ]);

    const order = orderResult.rows[0];

    // Create order items
    for (const item of cartItems) {
      await pool.query(`
        INSERT INTO order_items (order_id, product_id, product_name, quantity, unit_price, total_price, size, color, custom_input)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      `, [
        order.id, 
        item.product_id, 
        item.product_name, 
        item.quantity, 
        item.unit_price, 
        (item.quantity * parseFloat(item.unit_price)), 
        item.size, 
        item.color, 
        item.custom_input
      ]);
    }

    // Clear cart
    await pool.query(`
      DELETE FROM cart WHERE customer_id = $1
    `, [customerId]);

    // Update customer stats
    await pool.query(`
      UPDATE customers 
      SET total_orders = total_orders + 1,
          total_spent = total_spent + $1,
          average_order_value = (total_spent + $1) / (total_orders + 1),
          loyalty_points = loyalty_points + FLOOR($1 * 0.1)
      WHERE id = $2
    `, [total_amount, customerId]);

    res.json({ 
      message: 'Order created successfully', 
      order: order,
      orderNumber: orderNumber
    });
  } catch (error) {
    logger.error('Error creating order:', error);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// ========================================
// PAYPAL WEBHOOK ENDPOINT
// ========================================

// Test webhook endpoint with error handling
app.post('/api/test-webhook', express.json({ limit: '10mb' }), async (req, res) => {
  try {
    logger.info('🧪 Test webhook called with data:', JSON.stringify(req.body, null, 2));
    res.json({ success: true, message: 'Test webhook received', data: req.body });
  } catch (error) {
    logger.error('❌ Test webhook error:', error.message);
    res.status(400).json({ error: 'Invalid JSON data' });
  }
});

// Simple webhook test endpoint
app.get('/api/paypal/webhook', (req, res) => {
  logger.info('🔔 PayPal webhook GET request received!');
  logger.info('🔔 Request URL:', req.url);
  logger.info('🔔 Full URL:', req.protocol + '://' + req.get('host') + req.originalUrl);
  res.json({ 
    success: true, 
    message: 'PayPal webhook endpoint is accessible',
    timestamp: new Date().toISOString(),
    url: req.protocol + '://' + req.get('host') + req.originalUrl
  });
});
// Test PayPal webhook simulation
app.post('/api/test-paypal-webhook', express.json(), async (req, res) => {
  try {
    const { paymentId, orderId } = req.body;
    
    if (!paymentId || !orderId) {
      return res.status(400).json({ error: 'paymentId and orderId are required' });
    }
    
    // Simulate PayPal webhook data
    const webhookData = {
      id: `WH-${Date.now()}`,
      event_type: 'PAYMENT.CAPTURE.COMPLETED',
      create_time: new Date().toISOString(),
      resource_type: 'capture',
      resource: {
        id: paymentId,
        custom_id: orderId.toString(),
        status: 'COMPLETED',
        amount: {
          currency_code: 'USD',
          value: '25.00'
        }
      }
    };
    
    logger.info('🧪 Simulating PayPal webhook with data:', JSON.stringify(webhookData, null, 2));
    
    // Process the webhook
    await handlePaymentCompleted(webhookData);
    
    res.json({ 
      success: true, 
      message: 'PayPal webhook simulation completed',
      webhookData: webhookData
    });
  } catch (error) {
    logger.error('❌ Test PayPal webhook error:', error.message);
    res.status(500).json({ error: 'Webhook simulation failed' });
  }
});

// PayPal webhook endpoint for payment notifications
app.post('/api/paypal/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  logger.info('🔔 PayPal webhook endpoint called!');
  logger.info('🔔 Request method:', req.method);
  logger.info('🔔 Request headers:', req.headers);
  logger.info('🔔 Request body length:', req.body ? req.body.length : 'no body');
  logger.info('🔔 Request body type:', typeof req.body);
  logger.info('🔔 Request body preview:', req.body ? req.body.toString().substring(0, 200) + '...' : 'no body');
  
  try {
    const webhookId = process.env.PAYPAL_WEBHOOK_ID;
    const webhookSignature = req.headers['paypal-transmission-id'];
    const webhookCertId = req.headers['paypal-cert-id'];
    const webhookAuthAlgo = req.headers['paypal-auth-algo'];
    const webhookTransmissionTime = req.headers['paypal-transmission-time'];
    
    // For testing, we'll process webhooks even without proper headers
    if (!webhookId || !webhookSignature || !webhookCertId || !webhookAuthAlgo || !webhookTransmissionTime) {
      logger.warn('⚠️ Missing PayPal webhook headers - processing anyway for testing');
      // Don't return error, continue processing
    }

    // Verify webhook signature (in production, you should verify the signature)
    // For now, we'll process the webhook without verification for testing
    
    let webhookData;
    try {
      // Handle Buffer, string, and object body types
      if (Buffer.isBuffer(req.body)) {
        // Convert Buffer to string and parse JSON
        const bodyString = req.body.toString('utf8');
        logger.info('🔍 Webhook body string:', bodyString.substring(0, 200) + '...');
        webhookData = JSON.parse(bodyString);
      } else if (typeof req.body === 'string') {
        webhookData = JSON.parse(req.body);
      } else if (typeof req.body === 'object' && req.body !== null) {
        webhookData = req.body;
      } else {
        throw new Error('Invalid webhook body type: ' + typeof req.body);
      }
    } catch (parseError) {
      logger.error('❌ PayPal webhook JSON parsing error:', parseError.message);
      logger.error('❌ Webhook body type:', typeof req.body);
      logger.error('❌ Webhook body length:', req.body ? req.body.length : 'no body');
      logger.error('❌ Webhook body preview:', req.body ? req.body.toString().substring(0, 200) : 'no body');
      return res.status(400).json({ error: 'Invalid webhook data format' });
    }
    
    logger.info('🔔 PayPal webhook received - Event Type:', webhookData.event_type);
    logger.info('🔔 Webhook data:', JSON.stringify(webhookData, null, 2));
    logger.info('🔔 Webhook headers:', req.headers);

    // Handle different webhook events
    if (webhookData.event_type === 'PAYMENT.CAPTURE.COMPLETED') {
      logger.info('✅ Processing PAYMENT.CAPTURE.COMPLETED event');
      await handlePaymentCompleted(webhookData);
    } else if (webhookData.event_type === 'PAYMENT.CAPTURE.DENIED') {
      await handlePaymentDenied(webhookData);
    } else if (webhookData.event_type === 'PAYMENT.CAPTURE.REFUNDED') {
      await handlePaymentRefunded(webhookData);
    }

    res.status(200).json({ success: true });
  } catch (error) {
    logger.error('❌ PayPal webhook error:', error);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// Handle completed payment
async function handlePaymentCompleted(webhookData) {
  try {
    logger.info('🔍 Full webhook data structure:', JSON.stringify(webhookData, null, 2));
    
    const capture = webhookData.resource;
    logger.info('🔍 Webhook resource:', JSON.stringify(capture, null, 2));
    
    // The webhook sends the PayPal capture ID in the resource.id field
    // We need to find the order by looking for the PayPal Order ID in different possible fields
    let captureId = capture?.id || webhookData?.resource?.id;
    
    // Try multiple possible fields for the PayPal Order ID
    let paypalOrderId = capture?.parent_payment || 
                       capture?.order_id || 
                       webhookData?.resource?.parent_payment || 
                       webhookData?.resource?.order_id ||
                       capture?.supplementary_data?.related_ids?.order_id ||
                       webhookData?.resource?.supplementary_data?.related_ids?.order_id;
    
    logger.info('🔍 Capture ID from webhook:', captureId);
    logger.info('🔍 PayPal Order ID from capture:', paypalOrderId);
    logger.info('🔍 Capture parent_payment:', capture?.parent_payment);
    logger.info('🔍 Capture order_id:', capture?.order_id);
    logger.info('🔍 Webhook resource parent_payment:', webhookData?.resource?.parent_payment);
    logger.info('🔍 Webhook resource order_id:', webhookData?.resource?.order_id);
    logger.info('🔍 Capture supplementary_data:', capture?.supplementary_data);
    logger.info('🔍 Custom ID (our database order ID):', capture?.custom_id);
    logger.info('🔍 Full webhook data:', JSON.stringify(webhookData, null, 2));
    logger.info('🔍 Full capture object:', JSON.stringify(capture, null, 2));
    logger.info('🔍 All capture keys:', capture ? Object.keys(capture) : 'No capture');
    logger.info('🔍 All webhook keys:', Object.keys(webhookData));
    
    // If we still can't find the Order ID, try using the capture ID itself
    // Sometimes PayPal sends the Order ID as the capture ID
    if (!paypalOrderId) {
      logger.warn('⚠️ No PayPal Order ID found in expected fields, trying capture ID as Order ID');
      paypalOrderId = captureId;
    }
    
    if (!paypalOrderId) {
      logger.error('❌ No PayPal Order ID found in webhook data');
      logger.error('❌ Available keys in resource:', capture ? Object.keys(capture) : 'No resource');
      logger.error('❌ Available keys in webhook data:', Object.keys(webhookData));
      logger.error('❌ Full webhook data:', JSON.stringify(webhookData, null, 2));
      return;
    }
    
    // Find order by payment_id (PayPal Order ID)
    let orderResult = await pool.query(`
      SELECT id FROM orders WHERE payment_id = $1
    `, [paypalOrderId]);
    
    // If not found by Order ID, try searching by capture ID as fallback
    if (orderResult.rows.length === 0 && captureId && captureId !== paypalOrderId) {
      logger.warn('⚠️ Order not found by Order ID, trying capture ID as fallback');
      orderResult = await pool.query(`
        SELECT id FROM orders WHERE payment_id = $1
      `, [captureId]);
    }
    
    if (orderResult.rows.length === 0) {
      logger.error('❌ Order not found for PayPal Order ID:', paypalOrderId);
      logger.error('❌ Capture ID was:', captureId);
      logger.error('❌ Tried both Order ID and Capture ID in payment_id field');
      logger.error('❌ Available orders in database:');
      
      // Show recent orders for debugging
      const recentOrders = await pool.query(`
        SELECT id, payment_id, order_number, created_at 
        FROM orders 
        ORDER BY created_at DESC 
        LIMIT 5
      `);
      logger.error('❌ Recent orders:', recentOrders.rows);
      return;
    }
    
    const orderIdToUpdate = orderResult.rows[0].id;
    
    // Update the order with the actual payment ID from the webhook
    await pool.query(`
      UPDATE orders 
      SET status = 'pending',
          payment_status = 'completed', 
          payment_details = $1,
          payment_id = $2,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = $3
    `, [JSON.stringify(capture), capture.id, orderIdToUpdate]);

    // Get order details for email - use the order ID we just found
    const orderDetailsResult = await pool.query(`
      SELECT o.*, c.email, c.first_name, c.last_name
      FROM orders o
      JOIN customers c ON o.customer_id = c.id
      WHERE o.id = $1
    `, [orderIdToUpdate]);
    
    // Order should be found since we just updated it
    if (orderDetailsResult.rows.length === 0) {
      logger.error('❌ Order not found for ID:', orderIdToUpdate);
      return;
    }




    const order = orderDetailsResult.rows[0];

    // Get order items
    const itemsResult = await pool.query(`
      SELECT * FROM order_items WHERE order_id = $1
    `, [orderIdToUpdate]);

    const orderItems = itemsResult.rows;

    // Send confirmation emails
    logger.info('📧 About to send confirmation emails for order:', orderIdToUpdate);
    try {
    await sendPaymentConfirmationEmails(order, orderItems, capture);
      logger.info('✅ Confirmation emails sent successfully for order:', orderIdToUpdate);
    } catch (emailError) {
      logger.error('❌ Email sending failed for order:', orderIdToUpdate, emailError);
      // Don't throw - continue processing even if emails fail
    }

    logger.info('✅ Payment completed webhook processed successfully for order:', orderIdToUpdate);
  } catch (error) {
    logger.error('❌ Error handling payment completed:', error);
  }
}

// Handle denied payment
async function handlePaymentDenied(webhookData) {
  try {
    const capture = webhookData.resource;
    const paypalOrderId = capture?.parent_payment || capture?.order_id || capture?.id;
    
    if (paypalOrderId) {
      // Find order by payment_id
      const orderResult = await pool.query(`
        SELECT id FROM orders WHERE payment_id = $1
      `, [paypalOrderId]);
      
      if (orderResult.rows.length > 0) {
        const orderIdToUpdate = orderResult.rows[0].id;
        
      await pool.query(`
        UPDATE orders 
        SET payment_status = 'denied', 
            payment_details = $1,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $2
        `, [JSON.stringify(capture), orderIdToUpdate]);
        
        logger.info('❌ Payment denied for order:', orderIdToUpdate);
      } else {
        logger.error('❌ Order not found for PayPal Order ID:', paypalOrderId);
      }
    } else {
      logger.error('❌ No PayPal Order ID found in denied webhook data');
    }
  } catch (error) {
    logger.error('❌ Error handling payment denied:', error);
  }
}

// Handle refunded payment
async function handlePaymentRefunded(webhookData) {
  try {
    const capture = webhookData.resource;
    const paypalOrderId = capture?.parent_payment || capture?.order_id || capture?.id;
    
    if (paypalOrderId) {
      // Find order by payment_id
      const orderResult = await pool.query(`
        SELECT id FROM orders WHERE payment_id = $1
      `, [paypalOrderId]);
      
      if (orderResult.rows.length > 0) {
        const orderIdToUpdate = orderResult.rows[0].id;
        
      await pool.query(`
        UPDATE orders 
        SET payment_status = 'refunded', 
            payment_details = $1,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $2
        `, [JSON.stringify(capture), orderIdToUpdate]);
        
        logger.info('💰 Payment refunded for order:', orderIdToUpdate);
      } else {
        logger.error('❌ Order not found for PayPal Order ID:', paypalOrderId);
      }
    } else {
      logger.error('❌ No PayPal Order ID found in refunded webhook data');
    }
  } catch (error) {
    logger.error('❌ Error handling payment refunded:', error);
  }
}

// Send payment confirmation emails
async function sendPaymentConfirmationEmails(order, orderItems, paymentDetails) {
  try {
    logger.info('📧 Starting to send payment confirmation emails...');
    logger.info('📧 Order details:', {
      orderNumber: order.order_number,
      customerEmail: order.email,
      customerName: order.customer_name,
      totalAmount: order.total_amount
    });
    logger.info('📧 Order items count:', orderItems.length);
    logger.info('📧 Admin emails:', process.env.ADMIN_EMAIL, process.env.PLWGSCREATIVEAPPAREL_EMAIL);
    logger.info('📧 Resend API key configured:', !!process.env.RESEND_API_KEY);
    
    // Customer confirmation email
    try {
      await sendCustomerPaymentConfirmationEmail(order, orderItems, paymentDetails);
      logger.info('✅ Customer confirmation email sent');
    } catch (customerError) {
      logger.error('❌ Customer email failed:', customerError);
      throw customerError;
    }
    
    // Admin notification email
    try {
      await sendAdminPaymentNotificationEmail(order, orderItems, paymentDetails);
      logger.info('✅ Admin notification emails sent');
    } catch (adminError) {
      logger.error('❌ Admin email failed:', adminError);
      throw adminError;
    }
    
    logger.info('✅ Payment confirmation emails sent for order:', order.order_number);
  } catch (error) {
    logger.error('❌ Error sending payment confirmation emails:', error);
    throw error; // Re-throw to be caught by caller
  }
}

// Resend API email sending function
async function sendResendEmail(to, subject, html) {
  const resendApiKey = process.env.RESEND_API_KEY;
  if (!resendApiKey) {
    throw new Error('RESEND_API_KEY not configured');
  }

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${resendApiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'admin@plwgscreativeapparel.com',
      to: Array.isArray(to) ? to : [to],
      subject: subject,
      html: html
    })
  });

  const result = await response.json();
  
  if (!response.ok) {
    throw new Error(`Resend API error: ${result.message || 'Unknown error'}`);
  }

  logger.info(`✅ Email sent via Resend API. ID: ${result.id}`);
  return result;
}

// Send customer payment confirmation email
async function sendCustomerPaymentConfirmationEmail(order, orderItems, paymentDetails) {
  // Parse shipping address JSON
  let shippingAddress = 'Address not available';
  try {
    const addressData = JSON.parse(order.shipping_address);
    shippingAddress = `
      <strong>${addressData.first_name} ${addressData.last_name}</strong><br>
      ${addressData.address}<br>
      ${addressData.city}, ${addressData.state} ${addressData.zip}<br>
      Phone: ${addressData.phone}
    `;
  } catch (e) {
    // If parsing fails, use the raw string
    shippingAddress = order.shipping_address;
  }

  const customerEmailHTML = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Payment Confirmation - PLWG Creative Apparel</title>
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Inter:wght@300;400;500;600;700&display=swap');
        
        body { 
          font-family: 'Inter', Arial, sans-serif; 
          line-height: 1.6; 
          color: #e0e0e0; 
          margin: 0; 
          padding: 0; 
          background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #0f0f0f 100%);
          min-height: 100vh;
        }
        
        .email-container { 
          max-width: 600px; 
          margin: 0 auto; 
          background: linear-gradient(145deg, #1f1f1f 0%, #2a2a2a 100%);
          border-radius: 20px; 
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(0, 188, 212, 0.1);
          overflow: hidden;
          position: relative;
        }
        
        .email-container::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 4px;
          background: linear-gradient(90deg, #00bcd4, #4dd0e1, #00bcd4);
          background-size: 200% 100%;
          animation: shimmer 3s ease-in-out infinite;
        }
        
        @keyframes shimmer {
          0%, 100% { background-position: 200% 0; }
          50% { background-position: -200% 0; }
        }
        
        .header { 
          text-align: center; 
          padding: 40px 30px 30px; 
          background: linear-gradient(135deg, rgba(0, 188, 212, 0.1) 0%, rgba(77, 208, 225, 0.05) 100%);
          position: relative;
        }
        
        .logo { 
          font-family: 'Orbitron', monospace;
          font-size: 32px; 
          font-weight: 900; 
          background: linear-gradient(135deg, #00bcd4, #4dd0e1);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          margin-bottom: 15px;
          text-shadow: 0 0 30px rgba(0, 188, 212, 0.3);
        }
        
        .success-icon { 
          font-size: 64px; 
          margin-bottom: 20px;
          filter: drop-shadow(0 0 20px rgba(0, 188, 212, 0.6));
        }
        
        .header h1 {
          font-family: 'Orbitron', monospace;
          font-size: 28px;
          font-weight: 700;
          color: #00bcd4;
          margin: 0 0 10px 0;
          text-shadow: 0 0 20px rgba(0, 188, 212, 0.4);
        }
        
        .header p {
          color: #b0b0b0;
          font-size: 16px;
          margin: 0;
        }
        
        .order-details { 
          background: linear-gradient(145deg, rgba(0, 188, 212, 0.05) 0%, rgba(77, 208, 225, 0.02) 100%);
          padding: 30px; 
          margin: 0;
          border-top: 1px solid rgba(0, 188, 212, 0.2);
          border-bottom: 1px solid rgba(0, 188, 212, 0.2);
        }
        
        .order-details h3 {
          font-family: 'Orbitron', monospace;
          color: #00bcd4;
          font-size: 20px;
          margin: 0 0 20px 0;
          text-shadow: 0 0 10px rgba(0, 188, 212, 0.3);
        }
        
        .order-info {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 15px;
          margin-bottom: 25px;
        }
        
        .info-item {
          background: rgba(0, 0, 0, 0.3);
          padding: 15px;
          border-radius: 10px;
          border-left: 3px solid #00bcd4;
        }
        
        .info-label {
          color: #00bcd4;
          font-weight: 600;
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-bottom: 5px;
        }
        
        .info-value {
          color: #e0e0e0;
          font-size: 14px;
        }
        
        .items-section {
          margin-top: 25px;
        }
        
        .items-section h4 {
          font-family: 'Orbitron', monospace;
          color: #00bcd4;
          font-size: 18px;
          margin: 0 0 15px 0;
        }
        
        .item { 
          display: flex; 
          justify-content: space-between; 
          align-items: flex-start;
          padding: 20px; 
          background: rgba(0, 0, 0, 0.2);
          border-radius: 12px;
          margin-bottom: 15px;
          border: 1px solid rgba(0, 188, 212, 0.1);
          transition: all 0.3s ease;
        }
        
        .item:hover {
          background: rgba(0, 188, 212, 0.05);
          border-color: rgba(0, 188, 212, 0.3);
          transform: translateY(-2px);
        }
        
        .item:last-child { 
          margin-bottom: 0; 
        }
        
        .item-details {
          flex: 1;
        }
        
        .item-name {
          font-weight: 600;
          color: #e0e0e0;
          font-size: 16px;
          margin-bottom: 8px;
        }
        
        .item-specs {
          color: #b0b0b0;
          font-size: 14px;
          margin-bottom: 5px;
        }
        
        .item-custom {
          color: #00bcd4;
          font-size: 13px;
          font-style: italic;
        }
        
        .item-price {
          text-align: right;
          color: #00bcd4;
          font-weight: 600;
          font-size: 16px;
        }
        
        .total { 
          font-weight: 700; 
          font-size: 24px; 
          color: #00bcd4;
          background: linear-gradient(135deg, rgba(0, 188, 212, 0.1) 0%, rgba(77, 208, 225, 0.05) 100%);
          padding: 20px;
          border-radius: 12px;
          border: 2px solid rgba(0, 188, 212, 0.3);
          text-shadow: 0 0 20px rgba(0, 188, 212, 0.4);
        }
        
        .button-container {
          text-align: center;
          padding: 30px;
          background: linear-gradient(135deg, rgba(0, 0, 0, 0.3) 0%, rgba(0, 188, 212, 0.05) 100%);
        }
        
        .button { 
          display: inline-block; 
          background: linear-gradient(135deg, #00bcd4 0%, #4dd0e1 100%);
          color: #000; 
          padding: 15px 35px; 
          text-decoration: none; 
          border-radius: 25px; 
          margin: 0;
          font-weight: 600;
          font-size: 16px;
          text-transform: uppercase;
          letter-spacing: 1px;
          box-shadow: 0 8px 25px rgba(0, 188, 212, 0.3);
          transition: all 0.3s ease;
          border: none;
        }
        
        .button:hover {
          transform: translateY(-2px);
          box-shadow: 0 12px 35px rgba(0, 188, 212, 0.5);
        }
        
        .footer { 
          text-align: center; 
          padding: 30px; 
          background: linear-gradient(135deg, rgba(0, 0, 0, 0.5) 0%, rgba(0, 188, 212, 0.02) 100%);
          border-top: 1px solid rgba(0, 188, 212, 0.1);
        }
        
        .shipping-info {
          background: rgba(0, 188, 212, 0.05);
          padding: 20px;
          border-radius: 12px;
          margin: 20px 0;
          border: 1px solid rgba(0, 188, 212, 0.2);
        }
        
        .shipping-info h4 {
          font-family: 'Orbitron', monospace;
          color: #00bcd4;
          font-size: 16px;
          margin: 0 0 15px 0;
        }
        
        .shipping-address {
          color: #e0e0e0;
          line-height: 1.8;
        }
        
        .footer p {
          color: #b0b0b0;
          margin: 10px 0;
        }
        
        .footer a {
          color: #00bcd4;
          text-decoration: none;
        }
        
        .footer a:hover {
          text-shadow: 0 0 10px rgba(0, 188, 212, 0.6);
        }
        
        @media (max-width: 600px) {
          .email-container { margin: 0; border-radius: 0; }
          .order-info { grid-template-columns: 1fr; }
          .item { flex-direction: column; gap: 10px; }
          .item-price { text-align: left; }
        }
      </style>
    </head>
    <body>
      <div class="email-container">
        <div class="header">
          <div class="logo">PLWG Creative Apparel</div>
          <div class="success-icon">✅</div>
          <h1>Payment Confirmed!</h1>
          <p>Thank you for your order! Your payment has been successfully processed.</p>
        </div>
        
        <div class="order-details">
          <h3>Order Details</h3>
          
          <div class="order-info">
            <div class="info-item">
              <div class="info-label">Order Number</div>
              <div class="info-value">${order.order_number}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Order Date</div>
              <div class="info-value">${new Date(order.created_at).toLocaleDateString()}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Payment Method</div>
              <div class="info-value">PayPal</div>
            </div>
            <div class="info-item">
              <div class="info-label">Transaction ID</div>
              <div class="info-value">${paymentDetails.id}</div>
            </div>
          </div>
          
          <div class="items-section">
            <h4>Items Ordered</h4>
            ${orderItems.map(item => `
              <div class="item">
                <div class="item-details">
                  <div class="item-name">${item.product_name}</div>
                  <div class="item-specs">Size: ${item.size} | Color: ${item.color}</div>
                  ${item.custom_input ? `<div class="item-custom">Custom: ${item.custom_input}</div>` : ''}
                </div>
                <div class="item-price">
                  ${item.quantity} × $${item.unit_price} = $${(item.quantity * parseFloat(item.unit_price)).toFixed(2)}
                </div>
              </div>
            `).join('')}
            
            <div class="item total">
              <div>Total Amount</div>
              <div>$${parseFloat(order.total_amount || 0).toFixed(2)}</div>
            </div>
          </div>
        </div>
        
        <div class="button-container">
          <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/pages/order-success.html?order=${order.order_number}" class="button">View Order Details</a>
        </div>
        
        <div class="footer">
          <div class="shipping-info">
            <h4>Shipping Information</h4>
            <div class="shipping-address">${shippingAddress}</div>
          </div>
          
          <p>Your order will be processed and shipped within 24 hours.</p>
          <p><strong>Questions?</strong> Contact us at <a href="mailto:support@plwgscreativeapparel.com">support@plwgscreativeapparel.com</a></p>
        </div>
      </div>
    </body>
    </html>
  `;

  await sendResendEmail(
    order.email,
    `Payment Confirmed - Order ${order.order_number}`,
    customerEmailHTML
  );
  logger.info(`✅ Customer payment confirmation email sent to ${order.email}`);
}
// Send admin payment notification email
async function sendAdminPaymentNotificationEmail(order, orderItems, paymentDetails) {
  // Parse shipping address JSON
  let shippingAddress = 'Address not available';
  try {
    const addressData = JSON.parse(order.shipping_address);
    shippingAddress = `
      <strong>${addressData.first_name} ${addressData.last_name}</strong><br>
      ${addressData.address}<br>
      ${addressData.city}, ${addressData.state} ${addressData.zip}<br>
      Phone: ${addressData.phone}
    `;
  } catch (e) {
    // If parsing fails, use the raw string
    shippingAddress = order.shipping_address;
  }

  const adminEmailHTML = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>New Payment Received - PLWG Creative Apparel</title>
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Inter:wght@300;400;500;600;700&display=swap');
        
        body { 
          font-family: 'Inter', Arial, sans-serif; 
          line-height: 1.6; 
          color: #e0e0e0; 
          margin: 0; 
          padding: 0; 
          background: linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #0f0f0f 100%);
          min-height: 100vh;
        }
        
        .email-container { 
          max-width: 600px; 
          margin: 0 auto; 
          background: linear-gradient(145deg, #1f1f1f 0%, #2a2a2a 100%);
          border-radius: 20px; 
          box-shadow: 0 20px 40px rgba(0, 0, 0, 0.8), 0 0 0 1px rgba(0, 188, 212, 0.1);
          overflow: hidden;
          position: relative;
        }
        
        .email-container::before {
          content: '';
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          height: 4px;
          background: linear-gradient(90deg, #00bcd4, #4dd0e1, #00bcd4);
          background-size: 200% 100%;
          animation: shimmer 3s ease-in-out infinite;
        }
        
        @keyframes shimmer {
          0%, 100% { background-position: 200% 0; }
          50% { background-position: -200% 0; }
        }
        
        .header { 
          text-align: center; 
          padding: 40px 30px 30px; 
          background: linear-gradient(135deg, rgba(0, 188, 212, 0.1) 0%, rgba(77, 208, 225, 0.05) 100%);
          position: relative;
        }
        
        .logo { 
          font-family: 'Orbitron', monospace;
          font-size: 32px; 
          font-weight: 900; 
          background: linear-gradient(135deg, #00bcd4, #4dd0e1);
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          background-clip: text;
          margin-bottom: 15px;
          text-shadow: 0 0 30px rgba(0, 188, 212, 0.3);
        }
        
        .header h1 {
          font-family: 'Orbitron', monospace;
          font-size: 28px;
          font-weight: 700;
          color: #00bcd4;
          margin: 0 0 10px 0;
          text-shadow: 0 0 20px rgba(0, 188, 212, 0.4);
        }
        
        .alert { 
          background: linear-gradient(135deg, rgba(0, 188, 212, 0.1) 0%, rgba(77, 208, 225, 0.05) 100%);
          border: 2px solid rgba(0, 188, 212, 0.3); 
          color: #00bcd4; 
          padding: 20px; 
          border-radius: 12px; 
          margin: 20px 0;
          text-align: center;
          font-weight: 600;
        }
        
        .order-details { 
          background: linear-gradient(145deg, rgba(0, 188, 212, 0.05) 0%, rgba(77, 208, 225, 0.02) 100%);
          padding: 30px; 
          margin: 0;
          border-top: 1px solid rgba(0, 188, 212, 0.2);
          border-bottom: 1px solid rgba(0, 188, 212, 0.2);
        }
        
        .order-details h3 {
          font-family: 'Orbitron', monospace;
          color: #00bcd4;
          font-size: 20px;
          margin: 0 0 20px 0;
          text-shadow: 0 0 10px rgba(0, 188, 212, 0.3);
        }
        
        .order-info {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 15px;
          margin-bottom: 25px;
        }
        
        .info-item {
          background: rgba(0, 0, 0, 0.3);
          padding: 15px;
          border-radius: 10px;
          border-left: 3px solid #00bcd4;
        }
        
        .info-label {
          color: #00bcd4;
          font-weight: 600;
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: 1px;
          margin-bottom: 5px;
        }
        
        .info-value {
          color: #e0e0e0;
          font-size: 14px;
        }
        
        .items-section {
          margin-top: 25px;
        }
        
        .items-section h4 {
          font-family: 'Orbitron', monospace;
          color: #00bcd4;
          font-size: 18px;
          margin: 0 0 15px 0;
        }
        
        .item { 
          display: flex; 
          justify-content: space-between; 
          align-items: flex-start;
          padding: 20px; 
          background: rgba(0, 0, 0, 0.2);
          border-radius: 12px;
          margin-bottom: 15px;
          border: 1px solid rgba(0, 188, 212, 0.1);
          transition: all 0.3s ease;
        }
        
        .item:hover {
          background: rgba(0, 188, 212, 0.05);
          border-color: rgba(0, 188, 212, 0.3);
          transform: translateY(-2px);
        }
        
        .item:last-child { 
          margin-bottom: 0; 
        }
        
        .item-details {
          flex: 1;
        }
        
        .item-name {
          font-weight: 600;
          color: #e0e0e0;
          font-size: 16px;
          margin-bottom: 8px;
        }
        
        .item-specs {
          color: #b0b0b0;
          font-size: 14px;
          margin-bottom: 5px;
        }
        
        .item-custom {
          color: #00bcd4;
          font-size: 13px;
          font-style: italic;
        }
        
        .item-price {
          text-align: right;
          color: #00bcd4;
          font-weight: 600;
          font-size: 16px;
        }
        
        .total { 
          font-weight: 700; 
          font-size: 24px; 
          color: #00bcd4;
          background: linear-gradient(135deg, rgba(0, 188, 212, 0.1) 0%, rgba(77, 208, 225, 0.05) 100%);
          padding: 20px;
          border-radius: 12px;
          border: 2px solid rgba(0, 188, 212, 0.3);
          text-shadow: 0 0 20px rgba(0, 188, 212, 0.4);
        }
        
        .shipping-section {
          margin-top: 25px;
          background: rgba(0, 188, 212, 0.05);
          padding: 20px;
          border-radius: 12px;
          border: 1px solid rgba(0, 188, 212, 0.2);
        }
        
        .shipping-section h4 {
          font-family: 'Orbitron', monospace;
          color: #00bcd4;
          font-size: 16px;
          margin: 0 0 15px 0;
        }
        
        .shipping-address {
          color: #e0e0e0;
          line-height: 1.8;
        }
        
        .footer { 
          text-align: center; 
          padding: 30px; 
          background: linear-gradient(135deg, rgba(0, 0, 0, 0.5) 0%, rgba(0, 188, 212, 0.02) 100%);
          border-top: 1px solid rgba(0, 188, 212, 0.1);
        }
        
        .footer p {
          color: #b0b0b0;
          margin: 10px 0;
        }
        
        .footer a {
          color: #00bcd4;
          text-decoration: none;
          font-weight: 600;
          padding: 10px 20px;
          background: linear-gradient(135deg, rgba(0, 188, 212, 0.1) 0%, rgba(77, 208, 225, 0.05) 100%);
          border-radius: 8px;
          border: 1px solid rgba(0, 188, 212, 0.3);
          display: inline-block;
          margin-top: 10px;
          transition: all 0.3s ease;
        }
        
        .footer a:hover {
          background: linear-gradient(135deg, rgba(0, 188, 212, 0.2) 0%, rgba(77, 208, 225, 0.1) 100%);
          text-shadow: 0 0 10px rgba(0, 188, 212, 0.6);
          transform: translateY(-2px);
        }
        
        @media (max-width: 600px) {
          .email-container { margin: 0; border-radius: 0; }
          .order-info { grid-template-columns: 1fr; }
          .item { flex-direction: column; gap: 10px; }
          .item-price { text-align: left; }
        }
      </style>
    </head>
    <body>
      <div class="email-container">
        <div class="header">
          <div class="logo">PLWG Creative Apparel</div>
          <h1>💰 New Payment Received!</h1>
        </div>
        
        <div class="alert">
          <strong>Payment Status:</strong> COMPLETED<br>
          <strong>Payment Method:</strong> PayPal<br>
          <strong>Transaction ID:</strong> ${paymentDetails.id}
        </div>
        
        <div class="order-details">
          <h3>Order Information</h3>
          
          <div class="order-info">
            <div class="info-item">
              <div class="info-label">Order Number</div>
              <div class="info-value">${order.order_number}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Customer</div>
              <div class="info-value">${order.customer_name}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Email</div>
              <div class="info-value">${order.email}</div>
            </div>
            <div class="info-item">
              <div class="info-label">Order Date</div>
              <div class="info-value">${new Date(order.created_at).toLocaleDateString()}</div>
            </div>
          </div>
          
          <div class="items-section">
            <h4>Items Ordered</h4>
            ${orderItems.map(item => `
              <div class="item">
                <div class="item-details">
                  <div class="item-name">${item.product_name}</div>
                  <div class="item-specs">Size: ${item.size} | Color: ${item.color}</div>
                  ${item.custom_input ? `<div class="item-custom">Custom: ${item.custom_input}</div>` : ''}
                </div>
                <div class="item-price">
                  ${item.quantity} × $${item.unit_price} = $${(item.quantity * parseFloat(item.unit_price)).toFixed(2)}
                </div>
              </div>
            `).join('')}
            
            <div class="item total">
              <div>Total Amount</div>
              <div>$${parseFloat(order.total_amount || 0).toFixed(2)}</div>
            </div>
          </div>
          
          <div class="shipping-section">
            <h4>Shipping Address</h4>
            <div class="shipping-address">${shippingAddress}</div>
          </div>
        </div>
        
        <div class="footer">
          <p>This is an automated notification. Please process this order for shipping.</p>
          <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/admin-dashboard.html">View Orders in Admin Dashboard</a>
        </div>
      </div>
    </body>
    </html>
  `;

  // Send to all admin emails
  const adminEmails = [process.env.ADMIN_EMAIL, 'letsgetcreative@myyahoo.com', 'PlwgsCreativeApparel@yahoo.com'].filter(Boolean);
  
  await sendResendEmail(
    adminEmails,
    `💰 New Payment: ${order.order_number} - $${parseFloat(order.total_amount || 0).toFixed(2)}`,
    adminEmailHTML
  );
  logger.info(`✅ Admin payment notification sent to ${adminEmails.join(', ')}`);
}

// ========================================
// CATEGORY MANAGEMENT API ENDPOINTS
// ========================================

// Get all categories
app.get('/api/admin/categories', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, name, description, display_order, created_at, updated_at
      FROM categories 
      ORDER BY display_order ASC, name ASC
    `);
    
    res.json(result.rows);
  } catch (error) {
    logger.error('Error fetching categories:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// Create new category
app.post('/api/admin/categories', async (req, res) => {
  try {
    const { name, description, display_order } = req.body;
    
    // Validation
    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Category name is required' });
    }
    
    if (name.length > 100) {
      return res.status(400).json({ error: 'Category name must be 100 characters or less' });
    }
    
    // Check if category name already exists
    const existingCategory = await pool.query(
      'SELECT id FROM categories WHERE LOWER(name) = LOWER($1)',
      [name.trim()]
    );
    
    if (existingCategory.rows.length > 0) {
      return res.status(400).json({ error: 'Category name already exists' });
    }
    
    // Create category
    const result = await pool.query(`
      INSERT INTO categories (name, description, display_order, created_at, updated_at)
      VALUES ($1, $2, $3, NOW(), NOW())
      RETURNING id, name, description, display_order, created_at, updated_at
    `, [name.trim(), description || null, display_order || 1]);
    
    res.status(201).json(result.rows[0]);
  } catch (error) {
    logger.error('Error creating category:', error);
    res.status(500).json({ error: 'Failed to create category' });
  }
});

// Update category
app.put('/api/admin/categories/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, display_order } = req.body;
    
    // Validation
    if (!name || name.trim().length === 0) {
      return res.status(400).json({ error: 'Category name is required' });
    }
    
    if (name.length > 100) {
      return res.status(400).json({ error: 'Category name must be 100 characters or less' });
    }
    
    // Check if category exists
    const existingCategory = await pool.query(
      'SELECT id FROM categories WHERE id = $1',
      [id]
    );
    
    if (existingCategory.rows.length === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    // Check if new name conflicts with other categories
    const nameConflict = await pool.query(
      'SELECT id FROM categories WHERE LOWER(name) = LOWER($1) AND id != $2',
      [name.trim(), id]
    );
    
    if (nameConflict.rows.length > 0) {
      return res.status(400).json({ error: 'Category name already exists' });
    }
    
    // Update category
    const result = await pool.query(`
      UPDATE categories 
      SET name = $1, description = $2, display_order = $3, updated_at = NOW()
      WHERE id = $4
      RETURNING id, name, description, display_order, created_at, updated_at
    `, [name.trim(), description || null, display_order || 1, id]);
    
    // Update products that use this category name
    await pool.query(
      'UPDATE products SET category = $1 WHERE category = (SELECT name FROM categories WHERE id = $2)',
      [name.trim(), id]
    );
    
    res.json(result.rows[0]);
  } catch (error) {
    logger.error('Error updating category:', error);
    res.status(500).json({ error: 'Failed to update category' });
  }
});

// Delete category
app.delete('/api/admin/categories/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Get category info before deletion
    const categoryResult = await pool.query(
      'SELECT name FROM categories WHERE id = $1',
      [id]
    );
    
    if (categoryResult.rows.length === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }
    
    const categoryName = categoryResult.rows[0].name;
    
    // Move products to "Uncategorized" instead of deleting them
    await pool.query(
      'UPDATE products SET category = $1 WHERE category = $2',
      ['Uncategorized', categoryName]
    );
    
    // Delete the category
    await pool.query('DELETE FROM categories WHERE id = $1', [id]);
    
    res.json({ message: 'Category deleted successfully', products_moved: 'Uncategorized' });
  } catch (error) {
    logger.error('Error deleting category:', error);
    res.status(500).json({ error: 'Failed to delete category' });
  }
});

// Get category statistics
app.get('/api/admin/categories/stats', async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        c.name,
        c.id,
        COUNT(p.id) as product_count
      FROM categories c
      LEFT JOIN products p ON c.name = p.category
      GROUP BY c.id, c.name
      ORDER BY c.display_order ASC, c.name ASC
    `);
    
    res.json(stats.rows);
  } catch (error) {
    logger.error('Error fetching category stats:', error);
    res.status(500).json({ error: 'Failed to fetch category statistics' });
  }
});

// Get products with custom input fields enabled
app.get('/api/admin/products/custom-inputs', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        id,
        name,
        category,
        custom_birthday_enabled,
        custom_birthday_required,
        custom_birthday_fields,
        custom_birthday_labels,
        custom_birthday_char_limit,
        custom_lyrics_enabled,
        custom_lyrics_required,
        custom_lyrics_fields,
        custom_lyrics_labels,
        custom_lyrics_char_limit
      FROM products 
      WHERE custom_birthday_enabled = true OR custom_lyrics_enabled = true
      ORDER BY category, name
    `);
    
    res.json(result.rows);
  } catch (error) {
    logger.error('Error fetching products with custom inputs:', error);
    res.status(500).json({ error: 'Failed to fetch products with custom inputs' });
  }
});

// Get custom input configuration for a specific product
app.get('/api/admin/products/:id/custom-inputs', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(`
      SELECT 
        custom_birthday_enabled,
        custom_birthday_required,
        custom_birthday_fields,
        custom_birthday_labels,
        custom_birthday_char_limit,
        custom_lyrics_enabled,
        custom_lyrics_required,
        custom_lyrics_fields,
        custom_lyrics_labels,
        custom_lyrics_char_limit
      FROM products 
      WHERE id = $1
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Product not found' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    logger.error('Error fetching product custom inputs:', error);
    res.status(500).json({ error: 'Failed to fetch product custom inputs' });
  }
});

// Manual email trigger for testing (bypasses webhook)
app.post('/api/trigger-payment-email', async (req, res) => {
  try {
    const { orderNumber } = req.body;
    
    if (!orderNumber) {
      return res.status(400).json({ error: 'Order number is required' });
    }

    // Get order details
    const orderResult = await pool.query(`
      SELECT o.*, c.email, c.first_name, c.last_name
      FROM orders o
      LEFT JOIN customers c ON o.customer_id = c.id
      WHERE o.order_number = $1
    `, [orderNumber]);

    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const order = orderResult.rows[0];
    
    logger.info('📧 Order details for email:', {
      orderNumber: order.order_number,
      customerEmail: order.email,
      customerName: order.first_name + ' ' + order.last_name,
      totalAmount: order.total_amount
    });

    // Get order items
    const itemsResult = await pool.query(`
      SELECT oi.*, p.name as product_name, p.image_url
      FROM order_items oi
      LEFT JOIN products p ON oi.product_id = p.id
      WHERE oi.order_id = $1
    `, [order.id]);

    const orderItems = itemsResult.rows;
    
    logger.info('📦 Order items:', orderItems.length);

    // Send emails with detailed error handling
    try {
      await sendPaymentConfirmationEmails(order, orderItems, { id: 'manual-trigger' });
      logger.info('✅ Payment confirmation emails sent successfully');
    } catch (emailError) {
      logger.error('❌ Email sending failed:', emailError);
      return res.status(500).json({ 
        success: false,
        error: 'Email sending failed', 
        details: emailError.message,
        orderNumber: order.order_number
      });
    }

    res.json({ 
      success: true, 
      message: 'Payment confirmation emails sent manually',
      orderNumber: order.order_number,
      customerEmail: order.email
    });

  } catch (error) {
    logger.error('❌ Error triggering payment email:', error);
    res.status(500).json({ error: 'Failed to send emails', details: error.message });
  }
});

// Manual payment processing endpoint (for testing without webhooks)
app.post('/api/process-payment-manual', async (req, res) => {
  try {
    const { orderNumber, customerEmail, customerName, totalAmount, paymentId } = req.body;
    
    if (!orderNumber || !customerEmail || !customerName || !totalAmount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    logger.info('🔄 Manually processing payment for order:', orderNumber);
    
    // Create mock order data
    const mockOrder = {
      order_number: orderNumber,
      email: customerEmail,
      customer_name: customerName,
      total_amount: totalAmount,
      shipping_address: '123 Test St, Test City, TC 12345',
      created_at: new Date().toISOString()
    };
    
    const mockOrderItems = [{
      product_name: 'Test Product',
      size: 'M',
      color: 'Black',
      quantity: 1,
      unit_price: totalAmount
    }];
    
    const mockPaymentDetails = {
      id: paymentId || 'MANUAL-' + Date.now()
    };
    
    // Send emails
    await sendCustomerPaymentConfirmationEmail(mockOrder, mockOrderItems, mockPaymentDetails);
    await sendAdminPaymentNotificationEmail(mockOrder, mockOrderItems, mockPaymentDetails);
    
    logger.info('✅ Manual payment processing completed');
    return res.status(200).json({ 
      success: true, 
      message: 'Payment processed and emails sent',
      orderNumber: orderNumber
    });
    
  } catch (error) {
    logger.error('❌ Manual payment processing failed:', error);
    return res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});

// Test payment confirmation email endpoint
app.post('/api/test-payment-email', async (req, res) => {
  try {
    logger.info('🧪 Testing payment confirmation email...');
    
    // Create a mock order for testing
    const mockOrder = {
      order_number: 'TEST-' + Date.now(),
      email: 'letsgetcreative@myyahoo.com',
      customer_name: 'Test Customer',
      total_amount: '25.99',
      shipping_address: '123 Test St, Test City, TC 12345',
      created_at: new Date().toISOString()
    };
    
    const mockOrderItems = [{
      product_name: 'Test Product',
      size: 'M',
      color: 'Black',
      quantity: 1,
      unit_price: '25.99'
    }];
    
    const mockPaymentDetails = {
      id: 'TEST-PAYMENT-' + Date.now()
    };
    
    // Send test emails
    await sendCustomerPaymentConfirmationEmail(mockOrder, mockOrderItems, mockPaymentDetails);
    await sendAdminPaymentNotificationEmail(mockOrder, mockOrderItems, mockPaymentDetails);
    
    logger.info('✅ Test payment emails sent successfully');
    return res.status(200).json({ 
      success: true, 
      message: 'Test payment emails sent to letsgetcreative@myyahoo.com',
      orderNumber: mockOrder.order_number
    });
    
  } catch (error) {
    logger.error('❌ Test payment email failed:', error);
    return res.status(500).json({ 
      success: false, 
      error: error.message 
    });
  }
});
// Resend API test endpoint (FREE - 3000 emails/month)
app.get('/api/test-resend', async (req, res) => {
  try {
    logger.info('🧪 Testing Resend API...');
    
    const resendApiKey = process.env.RESEND_API_KEY;
    if (!resendApiKey) {
      return res.status(500).json({
        success: false,
        error: 'RESEND_API_KEY not configured',
        message: 'Please add RESEND_API_KEY to Railway environment variables'
      });
    }
    
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${resendApiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'admin@plwgscreativeapparel.com',
        to: ['mariaisabeljuarezgomez85@gmail.com'],
        subject: '🧪 Resend API Test - PLWG Creative Apparel',
        html: '<h2>🧪 Resend API Test</h2><p>This is a test email using Resend API.</p><p>Time: ' + new Date().toISOString() + '</p>'
      })
    });
    
    const result = await response.json();
    
    if (response.ok) {
      logger.info('✅ Resend API test successful:', result.id);
      res.json({
        success: true,
        message: 'Resend API test successful',
        emailId: result.id
      });
    } else {
      logger.error('❌ Resend API test failed:', result);
      res.status(500).json({
        success: false,
        error: 'Resend API test failed',
        details: result
      });
    }
    
  } catch (error) {
    logger.error('❌ Resend API test failed:', error);
    res.status(500).json({
      success: false,
      error: 'Resend API test failed',
      details: error.message
    });
  }
});

// Simple SMTP test endpoint - try all Zoho configurations
app.get('/api/test-smtp-simple', async (req, res) => {
  try {
    logger.info('🧪 Testing all Zoho SMTP configurations...');
    
    let workingConfig = null;
    let lastError = null;
    
    for (const config of smtpConfigs) {
      try {
        logger.info(`🧪 Testing ${config.name}: ${config.host}:${config.port} (secure: ${config.secure})`);
        
        const testTransporter = nodemailer.createTransport({
          host: config.host,
          port: config.port,
          secure: config.secure,
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASSWORD
          },
          connectionTimeout: 8000,
          greetingTimeout: 8000,
          socketTimeout: 8000
        });
        
        // Test connection
        await testTransporter.verify();
        logger.info(`✅ Connection successful with ${config.name}`);
        
        // Try to send a test email
        const testEmail = {
          from: process.env.EMAIL_FROM,
          to: 'mariaisabeljuarezgomez85@gmail.com',
          subject: `🧪 SMTP Test - ${config.name}`,
          text: `This is a test email using ${config.name} configuration.`,
          html: `<h2>🧪 SMTP Test - ${config.name}</h2><p>This is a test email using ${config.name} configuration.</p><p>Time: ${new Date().toISOString()}</p>`
        };
        
        const info = await testTransporter.sendMail(testEmail);
        logger.info(`✅ Email sent successfully with ${config.name}:`, info.messageId);
        
        workingConfig = config;
        break;
        
      } catch (error) {
        logger.info(`❌ ${config.name} failed:`, error.message);
        lastError = error;
      }
    }
    
    if (workingConfig) {
      res.json({
        success: true,
        message: `SMTP test successful with ${workingConfig.name}`,
        workingConfig: workingConfig,
        config: {
          host: workingConfig.host,
          port: workingConfig.port,
          secure: workingConfig.secure,
          user: process.env.SMTP_USER ? '***configured***' : 'NOT SET',
          from: process.env.EMAIL_FROM
        }
      });
    } else {
      res.status(500).json({
        success: false,
        error: 'All SMTP configurations failed',
        details: lastError ? lastError.message : 'Unknown error',
        testedConfigs: smtpConfigs.map(c => `${c.name}: ${c.host}:${c.port}`),
        config: {
          host: process.env.SMTP_HOST,
          port: process.env.SMTP_PORT,
          secure: process.env.SMTP_SECURE,
          user: process.env.SMTP_USER ? '***configured***' : 'NOT SET',
          from: process.env.EMAIL_FROM
        }
      });
    }
    
  } catch (error) {
    logger.error('❌ SMTP test failed:', error);
    res.status(500).json({
      success: false,
      error: 'SMTP test failed',
      details: error.message
    });
  }
});

// Email test endpoint
app.get('/api/test-email', async (req, res) => {
  try {
    logger.info('🧪 Testing email configuration...');
    logger.info('📧 SMTP Host:', process.env.SMTP_HOST);
    logger.info('📧 SMTP Port:', process.env.SMTP_PORT);
    logger.info('📧 SMTP User:', process.env.SMTP_USER);
    logger.info('📧 SMTP Secure:', process.env.SMTP_SECURE);
    logger.info('📧 Email From:', process.env.EMAIL_FROM);
    
    // Test current configuration first
    try {
      await transporter.verify();
      logger.info('✅ Current SMTP configuration is working!');
    } catch (error) {
      logger.info('❌ Current config failed, trying alternatives...');
      
      // Test alternative Zoho configurations
      const zohoConfigs = [
        { host: 'smtp.zoho.com', port: 587, secure: false },
        { host: 'smtp.zoho.eu', port: 465, secure: true },
        { host: 'smtp.zoho.eu', port: 587, secure: false }
      ];
      
      let workingConfig = null;
      for (const config of zohoConfigs) {
        try {
          logger.info(`🧪 Testing: ${config.host}:${config.port} (secure: ${config.secure})`);
          
          const testTransporter = nodemailer.createTransport({
            host: config.host,
            port: config.port,
            secure: config.secure,
            auth: {
              user: process.env.SMTP_USER,
              pass: process.env.SMTP_PASSWORD
            },
            connectionTimeout: 15000,
            greetingTimeout: 15000,
            socketTimeout: 15000
          });
          
          await testTransporter.verify();
          logger.info(`✅ SUCCESS with ${config.host}:${config.port}`);
          workingConfig = config;
          break;
        } catch (error) {
          logger.info(`❌ FAILED with ${config.host}:${config.port} - ${error.message}`);
        }
      }
      
      if (workingConfig) {
        // Update the main transporter with working config
        transporter.options.host = workingConfig.host;
        transporter.options.port = workingConfig.port;
        transporter.options.secure = workingConfig.secure;
        logger.info('🔄 Updated transporter with working configuration');
      }
    }
    
    // Test email configuration
    const testEmail = {
      from: process.env.EMAIL_FROM || 'test@example.com',
      to: process.env.ADMIN_EMAIL || 'test@example.com',
      subject: '🧪 Email Test - PLWG Creative Apparel',
      text: `This is a test email to verify your email configuration.
      
Time: ${new Date().toISOString()}
Server: ${process.env.NODE_ENV || 'development'}
SMTP Host: ${process.env.SMTP_HOST}
SMTP Port: ${process.env.SMTP_PORT}

If you receive this, your email configuration is working!`,
      html: `<h2>🧪 Email Test - PLWG Creative Apparel</h2>
<p>This is a test email to verify your email configuration.</p>
<ul>
<li><strong>Time:</strong> ${new Date().toISOString()}</li>
<li><strong>Server:</strong> ${process.env.NODE_ENV || 'development'}</li>
<li><strong>SMTP Host:</strong> ${process.env.SMTP_HOST}</li>
<li><strong>SMTP Port:</strong> ${process.env.SMTP_PORT}</li>
</ul>
<p><strong>If you receive this, your email configuration is working!</strong></p>`
    };

    // Verify transporter configuration
    await transporter.verify();
    logger.info('✅ SMTP connection verified successfully');
    
    // Send test email
    const info = await transporter.sendMail(testEmail);
    logger.info('✅ Test email sent successfully:', info.messageId);
    
    res.json({
      success: true,
      message: 'Test email sent successfully',
      messageId: info.messageId,
      config: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_SECURE,
        user: process.env.SMTP_USER ? '***configured***' : 'NOT SET',
        from: process.env.EMAIL_FROM
      }
    });
    
  } catch (error) {
    logger.error('❌ Email test failed:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      details: {
        code: error.code,
        command: error.command,
        responseCode: error.responseCode,
        response: error.response
      },
      config: {
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_SECURE,
        user: process.env.SMTP_USER ? '***configured***' : 'NOT SET',
        from: process.env.EMAIL_FROM
      }
    });
  }
});

// ========================================
// GLOBAL ERROR HANDLING
// ========================================

// Global error handler for unhandled errors
process.on('uncaughtException', (error) => {
  logger.error('❌ Uncaught Exception:', error);
  // Don't exit the process, just log the error
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit the process, just log the error
});

// JSON parsing error handler
app.use((error, req, res, next) => {
  if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
    logger.error('❌ JSON parsing error:', error.message);
    logger.error('❌ Request URL:', req.url);
    logger.error('❌ Request method:', req.method);
    logger.error('❌ Request headers:', req.headers);
    logger.error('❌ Raw body:', req.body);
    return res.status(400).json({ error: 'Invalid JSON format' });
  }
  next(error);
});

// Additional error handler for unhandled JSON parsing
app.use((error, req, res, next) => {
  if (error.message && error.message.includes('JSON')) {
    logger.error('❌ JSON Error:', error.message);
    logger.error('❌ Request URL:', req.url);
    logger.error('❌ Request method:', req.method);
    return res.status(400).json({ error: 'Invalid JSON format' });
  }
  next(error);
});

// 404 handler moved to AFTER all API routes to prevent blocking API requests

// Catch-all error handler to prevent server crashes
app.use((error, req, res, next) => {
  logger.error('❌ Unhandled error:', error.message);
  logger.error('❌ Request URL:', req.url);
  logger.error('❌ Request method:', req.method);
  logger.error('❌ Error stack:', error.stack);
  
  // Don't crash the server, just return an error response
  res.status(500).json({ 
    error: 'Internal server error',
    message: 'Something went wrong. Please try again.'
  });
});

// Customer Reviews Management API Endpoints

// Import all Etsy reviews from JSON file to database
app.post('/api/admin/customer-reviews/import', authenticateToken, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Database not available' });
  
  try {
    // Ensure table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_reviews (
        id SERIAL PRIMARY KEY,
        reviewer_name VARCHAR(255) NOT NULL,
        star_rating INTEGER NOT NULL CHECK (star_rating >= 1 AND star_rating <= 5),
        review_message TEXT NOT NULL,
        date_reviewed DATE NOT NULL,
        display_order INTEGER DEFAULT 0,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Read the etsy_reviews.json file
    const fs = require('fs');
    const path = require('path');
    const etsyReviewsPath = path.join(__dirname, 'etsy_reviews.json');
    
    if (!fs.existsSync(etsyReviewsPath)) {
      return res.status(404).json({ error: 'etsy_reviews.json file not found' });
    }

    const etsyReviewsData = fs.readFileSync(etsyReviewsPath, 'utf8');
    const etsyReviews = JSON.parse(etsyReviewsData);

    if (!Array.isArray(etsyReviews)) {
      return res.status(400).json({ error: 'Invalid JSON format in etsy_reviews.json' });
    }

    // Clear existing reviews
    await pool.query('DELETE FROM customer_reviews');

    // Import all reviews
    let importedCount = 0;
    for (let i = 0; i < etsyReviews.length; i++) {
      const review = etsyReviews[i];
      
      await pool.query(`
        INSERT INTO customer_reviews (reviewer_name, star_rating, review_message, date_reviewed, display_order, is_active)
        VALUES ($1, $2, $3, $4, $5, $6)
      `, [
        review.reviewer || 'Anonymous',
        review.star_rating || 5,
        review.message || '',
        review.date_reviewed || new Date().toISOString().split('T')[0],
        i + 1, // display_order
        true   // is_active
      ]);
      
      importedCount++;
    }

    res.json({ 
      success: true, 
      message: `Successfully imported ${importedCount} reviews from Etsy`,
      importedCount: importedCount
    });

  } catch (error) {
    logger.error('Error importing customer reviews:', error);
    res.status(500).json({ error: 'Failed to import reviews' });
  }
});

// Get all customer reviews for admin management
app.get('/api/admin/customer-reviews', authenticateToken, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Database not available' });
  
  try {
    // Ensure table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_reviews (
        id SERIAL PRIMARY KEY,
        reviewer_name VARCHAR(100) NOT NULL,
        star_rating INTEGER NOT NULL CHECK (star_rating BETWEEN 1 AND 5),
        review_message TEXT NOT NULL,
        date_reviewed VARCHAR(20),
        is_active BOOLEAN DEFAULT true,
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const result = await pool.query(`
      SELECT * FROM customer_reviews 
      ORDER BY display_order ASC, created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    logger.error('Error fetching customer reviews:', error);
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

// Get active customer reviews for homepage display
app.get('/api/customer-reviews', async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Database not available' });
  
  try {
    // Ensure table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_reviews (
        id SERIAL PRIMARY KEY,
        reviewer_name VARCHAR(100) NOT NULL,
        star_rating INTEGER NOT NULL CHECK (star_rating BETWEEN 1 AND 5),
        review_message TEXT NOT NULL,
        date_reviewed VARCHAR(20),
        is_active BOOLEAN DEFAULT true,
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const result = await pool.query(`
      SELECT reviewer_name, star_rating, review_message, date_reviewed 
      FROM customer_reviews 
      WHERE is_active = true 
      ORDER BY display_order ASC, created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    logger.error('Error fetching active customer reviews:', error);
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

// Add new customer review
app.post('/api/admin/customer-reviews', authenticateToken, [
  body('reviewer_name').notEmpty().withMessage('Reviewer name is required'),
  body('star_rating').isInt({ min: 1, max: 5 }).withMessage('Star rating must be between 1 and 5'),
  body('review_message').notEmpty().withMessage('Review message is required'),
  body('date_reviewed').optional()
], async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Database not available' });
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    // Ensure table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_reviews (
        id SERIAL PRIMARY KEY,
        reviewer_name VARCHAR(100) NOT NULL,
        star_rating INTEGER NOT NULL CHECK (star_rating BETWEEN 1 AND 5),
        review_message TEXT NOT NULL,
        date_reviewed VARCHAR(20),
        is_active BOOLEAN DEFAULT true,
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const { reviewer_name, star_rating, review_message, date_reviewed, display_order, is_active } = req.body;
    
    const result = await pool.query(`
      INSERT INTO customer_reviews (reviewer_name, star_rating, review_message, date_reviewed, display_order, is_active)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [reviewer_name, star_rating, review_message, date_reviewed || new Date().toLocaleDateString(), display_order || 0, is_active !== undefined ? is_active : true]);
    
    res.json({ success: true, review: result.rows[0] });
  } catch (error) {
    logger.error('Error adding customer review:', error);
    res.status(500).json({ error: 'Failed to add review' });
  }
});

// Update customer review
app.put('/api/admin/customer-reviews/:id', authenticateToken, [
  body('reviewer_name').notEmpty().withMessage('Reviewer name is required'),
  body('star_rating').isInt({ min: 1, max: 5 }).withMessage('Star rating must be between 1 and 5'),
  body('review_message').notEmpty().withMessage('Review message is required')
], async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Database not available' });
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    // Ensure table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_reviews (
        id SERIAL PRIMARY KEY,
        reviewer_name VARCHAR(100) NOT NULL,
        star_rating INTEGER NOT NULL CHECK (star_rating BETWEEN 1 AND 5),
        review_message TEXT NOT NULL,
        date_reviewed VARCHAR(20),
        is_active BOOLEAN DEFAULT true,
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const { id } = req.params;
    const { reviewer_name, star_rating, review_message, date_reviewed, is_active, display_order } = req.body;
    
    const result = await pool.query(`
      UPDATE customer_reviews 
      SET reviewer_name = $1, star_rating = $2, review_message = $3, 
          date_reviewed = $4, is_active = $5, display_order = $6, updated_at = CURRENT_TIMESTAMP
      WHERE id = $7
      RETURNING *
    `, [reviewer_name, star_rating, review_message, date_reviewed, is_active, display_order, id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Review not found' });
    }
    
    res.json({ success: true, review: result.rows[0] });
  } catch (error) {
    logger.error('Error updating customer review:', error);
    res.status(500).json({ error: 'Failed to update review' });
  }
});

// Delete customer review
app.delete('/api/admin/customer-reviews/:id', authenticateToken, async (req, res) => {
  if (!pool) return res.status(500).json({ error: 'Database not available' });
  
  try {
    // Ensure table exists
    await pool.query(`
      CREATE TABLE IF NOT EXISTS customer_reviews (
        id SERIAL PRIMARY KEY,
        reviewer_name VARCHAR(100) NOT NULL,
        star_rating INTEGER NOT NULL CHECK (star_rating BETWEEN 1 AND 5),
        review_message TEXT NOT NULL,
        date_reviewed VARCHAR(20),
        is_active BOOLEAN DEFAULT true,
        display_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    const { id } = req.params;
    
    const result = await pool.query(`
      DELETE FROM customer_reviews WHERE id = $1 RETURNING *
    `, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Review not found' });
    }
    
    res.json({ success: true, message: 'Review deleted successfully' });
  } catch (error) {
    logger.error('Error deleting customer review:', error);
    res.status(500).json({ error: 'Failed to delete review' });
  }
});

// Serve order success page
app.get('/order-success.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'order-success.html'));
});

// Serve order failure page
app.get('/order-failure.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'order-failure.html'));
});

// Serve account page
app.get('/account.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'account.html'));
});

// Serve cart page
app.get('/cart.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'cart.html'));
});

// Serve customer login page
app.get('/customer-login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'customer-login.html'));
});

// Serve shop page
app.get('/shop.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'shop.html'));
});

// Serve admin page
app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'admin.html'));
});

// Serve admin uploads page
app.get('/admin-uploads.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'admin-uploads.html'));
});

// Serve product edit page
app.get('/product-edit.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'product-edit.html'));
});

// Serve privacy policy page
app.get('/privacy-policy.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'privacy-policy.html'));
});

// Serve terms of service page
app.get('/terms-of-service.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'terms-of-service.html'));
});

// Serve about page
app.get('/about.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'about.html'));
});

// Serve contact page
app.get('/contact.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'contact.html'));
});

// Serve return policy page
app.get('/return-policy.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'return-policy.html'));
});

// Handle Chrome DevTools requests silently (prevents 404 spam)
app.get('/.well-known/appspecific/com.chrome.devtools.json', (req, res) => {
  res.status(204).end(); // No content, but not an error
});

// Serve category management page
app.get('/category-management.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'pages', 'category-management.html'));
});

// 404 handler for missing pages/files - must come AFTER all API routes
app.use((req, res, next) => {
  // Check if it's an API request
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ 
      error: 'API endpoint not found',
      path: req.path,
      method: req.method
    });
  }
  
  // For HTML pages, serve a proper 404 page
  if (req.path.endsWith('.html') || req.path === '/' || !req.path.includes('.')) {
    logger.warn(`🔍 404 - Page not found: ${req.path}`);
    return res.status(404).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Page Not Found - PLWGS Creative Apparel</title>
        <style>
          body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #0a0a0a; color: #fff; }
          h1 { color: #ff6b35; }
          a { color: #ff6b35; text-decoration: none; }
          a:hover { text-decoration: underline; }
        </style>
      </head>
      <body>
        <h1>404 - Page Not Found</h1>
        <p>The page you're looking for doesn't exist.</p>
        <p><a href="/">← Back to Homepage</a></p>
        <p><a href="/pages/shop.html">Browse Products</a></p>
      </body>
      </html>
    `);
  }
  
  // For other files (CSS, JS, images), return standard 404
  logger.warn(`🔍 404 - File not found: ${req.path}`);
  res.status(404).send('File not found');
});

// START SERVER IMMEDIATELY - Don't wait for admin init
console.log(`🌐 Starting Express server on port ${PORT}...`);
console.log(`📋 LOG_LEVEL is set to: ${LOG_LEVEL}`);
console.log(`📋 Available routes will be logged below...`);
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ SERVER RUNNING AND LISTENING on 0.0.0.0:${PORT}`);
  console.log(`🌍 Server is now accepting HTTP connections`);
    logger.info(`🚀 Admin Dashboard API server running on port ${PORT}`);
    logger.info(`📧 Email configured: ${process.env.EMAIL_FROM}`);
    logger.info(`🗄️ Database connected: ${process.env.DATABASE_URL ? 'Yes' : 'No'}`);
    
    // Configure server timeouts
    server.timeout = serverTimeout;
    server.keepAliveTimeout = 65000; // 65 seconds
    server.headersTimeout = 66000; // 66 seconds
    
  // Initialize admin credentials in background (non-blocking)
  console.log('🔧 Initializing admin credentials in background...');
  initializeAdminCredentials().then(() => {
    console.log('✅ Admin credentials initialized');
    logger.info(`🔐 Admin email: ${ADMIN_EMAIL_MEMO}`);
    logger.info(`🏷️ Category management system active`);
    
    // Initialize database in background (non-blocking)
    initializeDatabase().catch(err => {
      logger.error('❌ Database initialization failed, but server continues:', err.message);
  });
}).catch(err => {
  logger.error('❌ Failed to initialize admin credentials:', err);
    // Don't exit - server can still run for OAuth, public routes, etc.
  });
});

module.exports = app; 