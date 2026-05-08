/**
 * emailValidator.js
 * Core validation logic:
 *  1. Syntax check (regex)
 *  2. Domain / DNS lookup
 *  3. MX record lookup
 *  4. Provider classification (known-blocker vs verifiable)
 *  5. Catch-all detection (test with a random impossible address)
 *  6. SMTP handshake (EHLO → MAIL FROM → RCPT TO → QUIT)
 *     — never actually sends a message
 */

const dnsStandard = require("dns");
const dns = dnsStandard.promises;

// Set custom DNS servers if provided in .env (e.g. DNS_SERVERS=8.8.8.8,1.1.1.1)
const customDns = process.env.DNS_SERVERS;
if (customDns) {
  const servers = customDns.split(",").map(s => s.trim());
  console.log(`📡 Setting custom DNS servers: ${servers.join(", ")}`);
  dnsStandard.setServers(servers);
}
const net = require("net");

// ---------------------------------------------------------------------------
// Known providers that block external SMTP probing on port 25.
// For these, SMTP verification is impossible — we honestly report it.
// ---------------------------------------------------------------------------
const UNVERIFIABLE_MX_PATTERNS = [
  /google\.com$/i,
  /googlemail\.com$/i,
  /smtp\.google\.com$/i,
  /outlook\.com$/i,
  /hotmail\.com$/i,
  /protection\.outlook\.com$/i,
  /mail\.protection\.outlook\.com$/i,
  /yahoo\.com$/i,
  /yahoodns\.net$/i,
  /aol\.com$/i,
  /icloud\.com$/i,
  /me\.com$/i,
  /protonmail\.ch$/i,
  /proton\.me$/i,
  /zoho\.com$/i,
  /zohomail\.com$/i,
  /amazonses\.com$/i,
  /awsapps\.com$/i,
];

function isMxUnverifiable(mxHost) {
  return UNVERIFIABLE_MX_PATTERNS.some((pattern) => pattern.test(mxHost));
}

function getProviderName(mxHost) {
  if (/google/i.test(mxHost)) return "Google";
  if (/outlook|hotmail|microsoft/i.test(mxHost))
    return "Microsoft (Outlook/Office365)";
  if (/yahoo/i.test(mxHost)) return "Yahoo";
  if (/aol/i.test(mxHost)) return "AOL";
  if (/icloud|apple/i.test(mxHost)) return "Apple iCloud";
  if (/proton/i.test(mxHost)) return "ProtonMail";
  if (/zoho/i.test(mxHost)) return "Zoho";
  if (/amazon/i.test(mxHost)) return "Amazon";
  return null;
}

// ---------------------------------------------------------------------------
// 1. Syntax validation
// ---------------------------------------------------------------------------
const EMAIL_REGEX =
  /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

function validateSyntax(email) {
  if (!email || typeof email !== "string") {
    return { valid: false, reason: "Email must be a non-empty string" };
  }
  const trimmed = email.trim().toLowerCase();
  if (trimmed.length > 254) {
    return {
      valid: false,
      reason: "Email exceeds maximum length of 254 characters",
    };
  }
  const [local, domain] = trimmed.split("@");
  if (!local || !domain) {
    return { valid: false, reason: "Email must contain exactly one @ symbol" };
  }
  if (local.length > 64) {
    return {
      valid: false,
      reason: "Local part exceeds maximum length of 64 characters",
    };
  }
  if (!EMAIL_REGEX.test(trimmed)) {
    return { valid: false, reason: "Email format is invalid" };
  }
  return { valid: true, email: trimmed, local, domain };
}

// ---------------------------------------------------------------------------
// 2. MX record lookup
// ---------------------------------------------------------------------------
async function lookupMX(domain) {
  try {
    try {
      await dns.lookup(domain);
    } catch {
      return {
        valid: false,
        reason: `Domain "${domain}" does not exist or cannot be resolved`,
      };
    }
    const records = await dns.resolveMx(domain);
    if (!records || records.length === 0) {
      return { valid: false, reason: `Domain "${domain}" has no MX records` };
    }
    const sorted = records.sort((a, b) => a.priority - b.priority);
    return {
      valid: true,
      records: sorted.map((r) => ({
        exchange: r.exchange,
        priority: r.priority,
      })),
      primary: sorted[0].exchange,
    };
    } catch (err) {
    if (err.code === "ECONNREFUSED") {
      // Fallback: Try setting public DNS if system DNS is refused
      try {
        console.warn(`⚠️ DNS refused. Retrying with Google DNS (8.8.8.8)...`);
        dnsStandard.setServers(["8.8.8.8", "1.1.1.1"]);
        const records = await dns.resolveMx(domain);
        if (records && records.length > 0) {
          const sorted = records.sort((a, b) => a.priority - b.priority);
          return {
            valid: true,
            records: sorted.map((r) => ({ exchange: r.exchange, priority: r.priority })),
            primary: sorted[0].exchange,
          };
        }
      } catch (fallbackErr) {
        return { valid: false, reason: `DNS lookup failed (even with fallback): ${fallbackErr.message}` };
      }
    }
    if (err.code === "ENODATA" || err.code === "ENOTFOUND") {
      return { valid: false, reason: `No MX records found for "${domain}"` };
    }
    return { valid: false, reason: `DNS lookup failed: ${err.message}` };
  }
}

// ---------------------------------------------------------------------------
// 3. SMTP handshake
// ---------------------------------------------------------------------------
function smtpCheck(mxHost, email, fromEmail, timeoutMs) {
  return new Promise((resolve) => {
    const timeout = parseInt(timeoutMs, 10) || 5000;
    const steps = [];
    let resolved = false;
    let buffer = "";

    function done(result) {
      if (!resolved) {
        resolved = true;
        socket.destroy();
        resolve({ ...result, steps });
      }
    }

    const socket = net.createConnection({ host: mxHost, port: 25 });
    socket.setTimeout(timeout);

    socket.on("timeout", () => {
      done({
        valid: null,
        reason: "SMTP connection timed out",
        timedOut: true,
        inconclusive: true,
      });
    });
    socket.on("error", (err) => {
      if (err.code === "ECONNREFUSED") {
        done({
          valid: null,
          reason: "SMTP port 25 refused",
          inconclusive: true,
        });
      } else {
        done({
          valid: null,
          reason: `SMTP error: ${err.message}`,
          inconclusive: true,
        });
      }
    });

    let stage = "connect";

    socket.on("data", (data) => {
      buffer += data.toString();
      const lines = buffer.split("\r\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (!line) continue;
        steps.push(`← ${line}`);
        const code = parseInt(line.substring(0, 3), 10);
        const isLast = line[3] === " ";
        if (!isLast) continue;

        switch (stage) {
          case "connect":
            if (code === 220) {
              stage = "ehlo";
              const cmd = `EHLO validator\r\n`;
              steps.push(`→ ${cmd.trim()}`);
              socket.write(cmd);
            } else {
              done({
                valid: false,
                reason: `SMTP rejected connection: ${line}`,
              });
            }
            break;
          case "ehlo":
            if (code === 250) {
              stage = "mail_from";
              const cmd = `MAIL FROM:<${fromEmail}>\r\n`;
              steps.push(`→ ${cmd.trim()}`);
              socket.write(cmd);
            } else {
              done({
                valid: null,
                reason: `EHLO rejected: ${line}`,
                inconclusive: true,
              });
            }
            break;
          case "mail_from":
            if (code === 250) {
              stage = "rcpt_to";
              const cmd = `RCPT TO:<${email}>\r\n`;
              steps.push(`→ ${cmd.trim()}`);
              socket.write(cmd);
            } else {
              done({
                valid: null,
                reason: `MAIL FROM rejected: ${line}`,
                inconclusive: true,
              });
            }
            break;
          case "rcpt_to":
            stage = "quit";
            socket.write("QUIT\r\n");
            steps.push(`→ QUIT`);
            if (code === 250 || code === 251) {
              done({
                valid: true,
                rcptCode: code,
                reason: "Mailbox accepted by SMTP server",
              });
            } else if ([550, 551, 553, 554].includes(code)) {
              done({
                valid: false,
                rcptCode: code,
                reason: `Mailbox does not exist (SMTP ${code}): ${line}`,
              });
            } else if ([450, 451, 452].includes(code)) {
              done({
                valid: null,
                rcptCode: code,
                reason: `Temporarily unavailable (greylisting?): ${line}`,
                inconclusive: true,
              });
            } else {
              done({
                valid: null,
                rcptCode: code,
                reason: `Unexpected SMTP response (${code}): ${line}`,
                inconclusive: true,
              });
            }
            break;
          case "quit":
            done({ valid: true, reason: "Mailbox accepted" });
            break;
        }
      }
    });
  });
}

// ---------------------------------------------------------------------------
// 4. Catch-all detection
//    Probe with a guaranteed-random address on the same domain.
//    If accepted → catch-all → we cannot trust a real 250.
// ---------------------------------------------------------------------------
async function detectCatchAll(mxHost, domain, fromEmail, timeoutMs) {
  const randomLocal = `catchall_probe_${Date.now()}_${Math.random().toString(36).slice(2, 12)}`;
  const probeEmail = `${randomLocal}@${domain}`;
  const result = await smtpCheck(mxHost, probeEmail, fromEmail, timeoutMs);
  return {
    isCatchAll: result.valid === true,
    inconclusive: result.inconclusive || result.timedOut || false,
    reason: result.reason,
    probeEmail,
  };
}

// ---------------------------------------------------------------------------
// 5. Main validate function
// ---------------------------------------------------------------------------
async function validateEmail(email, options = {}) {
  const fromEmail = options.fromEmail || "verify@example.com";
  const smtpTimeout = options.smtpTimeout || 5000;
  const skipSmtp = options.skipSmtp || false;

  const result = {
    email: null,
    valid: false,
    checks: {
      syntax: { passed: false },
      dns: { passed: false },
      mx: { passed: false, records: [] },
      provider: { known: false, name: null, verifiable: true },
      catchAll: { detected: false, checked: false, inconclusive: false },
      smtp: { passed: null, inconclusive: false },
    },
    reason: null,
    score: 0,
  };

  // --- Syntax ---
  const syntaxResult = validateSyntax(email);
  if (!syntaxResult.valid) {
    result.checks.syntax = { passed: false, reason: syntaxResult.reason };
    result.reason = syntaxResult.reason;
    return result;
  }
  result.checks.syntax = { passed: true };
  result.email = syntaxResult.email;
  const { domain } = syntaxResult;
  result.score = 20;

  // --- MX ---
  const mxResult = await lookupMX(domain);
  if (!mxResult.valid) {
    result.checks.dns = { passed: false, reason: mxResult.reason };
    result.checks.mx = { passed: false, reason: mxResult.reason };
    result.reason = mxResult.reason;
    return result;
  }
  result.checks.dns = { passed: true };
  result.checks.mx = {
    passed: true,
    records: mxResult.records,
    primary: mxResult.primary,
  };
  result.score = 60;

  // --- Provider classification ---
  const providerName = getProviderName(mxResult.primary);
  const verifiable = !isMxUnverifiable(mxResult.primary);
  result.checks.provider = {
    known: !!providerName,
    name: providerName,
    verifiable,
    mxHost: mxResult.primary,
  };

  // Known unverifiable provider — be honest
  if (!verifiable) {
    result.valid = true;
    result.checks.smtp = {
      passed: null,
      inconclusive: true,
      skippedReason: "provider_blocks_smtp",
      reason: `${providerName || "This provider"} blocks external SMTP probing. Individual mailbox existence cannot be verified without sending an email.`,
    };
    result.checks.catchAll = {
      detected: false,
      checked: false,
      inconclusive: true,
      reason: "Skipped — provider blocks SMTP",
    };
    result.reason = `Domain and MX are valid (${providerName || mxResult.primary}). Cannot confirm mailbox — provider blocks SMTP checks.`;
    result.score = 65;
    return result;
  }

  if (skipSmtp) {
    result.valid = true;
    result.checks.smtp = {
      passed: null,
      inconclusive: true,
      reason: "SMTP check skipped by request",
    };
    result.checks.catchAll = {
      detected: false,
      checked: false,
      reason: "Skipped",
    };
    result.reason = "MX records found — SMTP check skipped";
    result.score = 60;
    return result;
  }

  // --- Run catch-all probe + real SMTP check in parallel ---
  const [catchAllResult, smtpResult] = await Promise.all([
    detectCatchAll(mxResult.primary, domain, fromEmail, smtpTimeout),
    smtpCheck(mxResult.primary, syntaxResult.email, fromEmail, smtpTimeout),
  ]);

  result.checks.catchAll = {
    checked: true,
    detected: catchAllResult.isCatchAll,
    inconclusive: catchAllResult.inconclusive,
    probeEmail: catchAllResult.probeEmail,
    reason: catchAllResult.isCatchAll
      ? "Server accepts all addresses (catch-all) — mailbox existence unconfirmable"
      : catchAllResult.inconclusive
        ? "Could not determine catch-all status"
        : "Not a catch-all — server rejects unknown addresses",
  };

  result.checks.smtp = {
    passed: smtpResult.valid,
    inconclusive: smtpResult.inconclusive || false,
    timedOut: smtpResult.timedOut || false,
    rcptCode: smtpResult.rcptCode,
    reason: smtpResult.reason,
    steps: smtpResult.steps,
    mxHost: mxResult.primary,
  };

  // Final verdict
  if (smtpResult.valid === false) {
    result.valid = false;
    result.reason = smtpResult.reason;
    result.score = 5;
  } else if (smtpResult.valid === true && catchAllResult.isCatchAll) {
    result.valid = true;
    result.reason =
      "Server accepted the address, but this is a catch-all domain — individual mailbox unconfirmable.";
    result.score = 55;
  } else if (smtpResult.valid === true && !catchAllResult.isCatchAll) {
    result.valid = true;
    result.reason =
      "Mailbox confirmed — accepted by SMTP and domain is not catch-all";
    result.score = 100;
  } else {
    result.valid = true;
    result.reason = `MX records valid. SMTP inconclusive: ${smtpResult.reason}`;
    result.score = 65;
  }

  return result;
}

module.exports = { validateEmail };
