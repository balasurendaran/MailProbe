/**
 * server.js — Email Validation API
 *
 * Endpoints:
 *   POST /api/validate         — validate a single email
 *   POST /api/validate/batch   — validate up to 10 emails at once
 *   GET  /api/health           — health check
 */

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const { validateEmail } = require("./emailValidator");

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Security middleware
// ---------------------------------------------------------------------------
app.use(helmet({ contentSecurityPolicy: false })); // CSP off so demo UI works inline
app.use(express.json({ limit: "16kb" }));

// CORS
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "*").split(",").map((o) => o.trim());
app.use(
  cors({
    origin: allowedOrigins.includes("*") ? "*" : allowedOrigins,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "X-API-Key", "Authorization"],
  })
);

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 60_000, // 1 min
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) || 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please slow down.", code: "RATE_LIMITED" },
});
app.use("/api/", limiter);

// ---------------------------------------------------------------------------
// Optional API key middleware
// ---------------------------------------------------------------------------
function apiKeyAuth(req, res, next) {
  const requiredKey = process.env.API_KEY;
  if (!requiredKey) return next(); // auth disabled

  const provided =
    req.headers["x-api-key"] ||
    (req.headers["authorization"] || "").replace(/^Bearer\s+/i, "");

  if (!provided || provided !== requiredKey) {
    return res.status(401).json({ error: "Unauthorized — invalid or missing API key", code: "UNAUTHORIZED" });
  }
  next();
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Health check (no auth required)
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString(), version: "1.0.0" });
});

// Single email validation
app.post("/api/validate", apiKeyAuth, async (req, res) => {
  const { email, skip_smtp } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Missing required field: email", code: "MISSING_EMAIL" });
  }

  try {
    const result = await validateEmail(email, {
      fromEmail: process.env.SMTP_FROM_EMAIL || "verify@example.com",
      smtpTimeout: parseInt(process.env.SMTP_TIMEOUT_MS, 10) || 5000,
      skipSmtp: skip_smtp === true,
    });

    const statusCode = result.valid ? 200 : 422;
    return res.status(statusCode).json({
      success: true,
      data: result,
      meta: { timestamp: new Date().toISOString(), skip_smtp: skip_smtp === true },
    });
  } catch (err) {
    console.error("Validation error:", err);
    return res.status(500).json({ error: "Internal validation error", code: "INTERNAL_ERROR" });
  }
});

// Batch email validation (up to 10)
app.post("/api/validate/batch", apiKeyAuth, async (req, res) => {
  const { emails, skip_smtp } = req.body;

  if (!Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({ error: "Field 'emails' must be a non-empty array", code: "INVALID_INPUT" });
  }
  if (emails.length > 10) {
    return res.status(400).json({ error: "Batch limit is 10 emails per request", code: "BATCH_LIMIT_EXCEEDED" });
  }

  try {
    const results = await Promise.all(
      emails.map((email) =>
        validateEmail(email, {
          fromEmail: process.env.SMTP_FROM_EMAIL || "verify@example.com",
          smtpTimeout: parseInt(process.env.SMTP_TIMEOUT_MS, 10) || 5000,
          skipSmtp: skip_smtp === true,
        }).catch((err) => ({
          email,
          valid: false,
          error: err.message,
          checks: {},
          score: 0,
        }))
      )
    );

    return res.json({
      success: true,
      data: {
        total: results.length,
        valid: results.filter((r) => r.valid).length,
        invalid: results.filter((r) => !r.valid).length,
        results,
      },
      meta: { timestamp: new Date().toISOString() },
    });
  } catch (err) {
    console.error("Batch validation error:", err);
    return res.status(500).json({ error: "Internal validation error", code: "INTERNAL_ERROR" });
  }
});

// Serve demo UI
app.use(express.static(path.join(__dirname, "../public")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "../public/index.html"));
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: "Route not found", code: "NOT_FOUND" });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`\n🚀  Email Validator API running on http://localhost:${PORT}`);
  console.log(`📋  API Key auth: ${process.env.API_KEY ? "ENABLED" : "DISABLED"}`);
  console.log(`🌐  CORS origins: ${allowedOrigins.join(", ")}`);
  console.log(`\nEndpoints:`);
  console.log(`  GET  http://localhost:${PORT}/api/health`);
  console.log(`  POST http://localhost:${PORT}/api/validate`);
  console.log(`  POST http://localhost:${PORT}/api/validate/batch\n`);
});

module.exports = app;
