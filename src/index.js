/**
 * GHOTI RESELLER — Cloudflare Worker for Telegram Withdraw Notifications
 * Verifies Firebase Auth ID Token cryptographically using Google X.509 Public Keys
 */

const ALLOWED_ORIGINS = [
  "https://reseller.ghotimarket.com",
  "http://localhost:3000",
  "http://127.0.0.1:5500"
];

const GOOGLE_CERTS_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "";
    const corsHeaders = buildCorsHeaders(origin);

    // 1. Handle CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // 2. Allow only POST requests
    if (request.method !== "POST") {
      return jsonResponse(
        { success: false, error: "Method Not Allowed. Only POST is accepted." },
        405,
        corsHeaders
      );
    }

    // 3. Validate Environment Secrets
    if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID || !env.FIREBASE_PROJECT_ID) {
      return jsonResponse(
        { success: false, error: "Server configuration missing." },
        500,
        corsHeaders
      );
    }

    try {
      // 4. Extract & Verify Firebase ID Token
      const authHeader = request.headers.get("Authorization") || "";
      if (!authHeader.startsWith("Bearer ")) {
        return jsonResponse(
          { success: false, error: "Unauthorized: Missing Bearer token." },
          401,
          corsHeaders
        );
      }

      const idToken = authHeader.slice(7).trim();
      const verifiedToken = await verifyFirebaseIdToken(idToken, env.FIREBASE_PROJECT_ID);

      // 5. Parse & Validate Request Payload
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          { success: false, error: "Invalid JSON payload." },
          400,
          corsHeaders
        );
      }

      const { uid, amount, PM, paymentNumber } = body || {};

      // Ensure Token UID strictly matches Payload UID
      if (!uid || typeof uid !== "string" || uid !== verifiedToken.uid) {
        return jsonResponse(
          { success: false, error: "Forbidden: UID mismatch." },
          403,
          corsHeaders
        );
      }

      const numericAmount = Number(amount);
      if (!Number.isInteger(numericAmount) || numericAmount < 100) {
        return jsonResponse(
          { success: false, error: "Invalid withdraw amount." },
          400,
          corsHeaders
        );
      }

      if (PM !== "bkash" && PM !== "nagad") {
        return jsonResponse(
          { success: false, error: "Invalid payment method." },
          400,
          corsHeaders
        );
      }

      if (typeof paymentNumber !== "string" || !/^01\d{9}$/.test(paymentNumber)) {
        return jsonResponse(
          { success: false, error: "Invalid 11-digit Bangladeshi mobile number." },
          400,
          corsHeaders
        );
      }

      // 6. Format Request Time in Bangladesh Standard Time (Asia/Dhaka)
      const requestTime = new Intl.DateTimeFormat("en-GB", {
        timeZone: "Asia/Dhaka",
        year: "numeric",
        month: "short",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true
      }).format(new Date());

      const methodLabel = PM === "bkash" ? "bKash" : "Nagad";

      // 7. Construct Professional Telegram Message (No Emojis)
      const telegramText = [
        "<b>GHOTI RESELLER NEW WITHDRAW REQUEST</b>",
        "",
        "নতুন একটি Withdraw Request জমা হয়েছে।",
        "",
        `<b>Reseller UID:</b> <code>${escapeHtml(uid)}</code>`,
        `<b>Withdraw Amount:</b> ৳${numericAmount.toLocaleString("en-US")}`,
        `<b>Payment Method:</b> ${methodLabel}`,
        `<b>Payment Number:</b> <code>${escapeHtml(paymentNumber)}</code>`,
        `<b>Request Time:</b> ${escapeHtml(requestTime)} (BST)`,
        `<b>Status:</b> PENDING`,
        "",
        `<b>Website:</b> https://reseller.ghotimarket.com`
      ].join("\n");

      // 8. Send Message via Telegram Bot API
      const tgUrl = `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`;
      const tgResponse = await fetch(tgUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: env.TELEGRAM_CHAT_ID,
          text: telegramText,
          parse_mode: "HTML",
          disable_web_page_preview: true
        })
      });

      const tgResult = await tgResponse.json();

      if (!tgResponse.ok || !tgResult.ok) {
        return jsonResponse(
          {
            success: false,
            error: "Telegram API failed to deliver message.",
            details: tgResult.description || "Unknown Telegram error"
          },
          502,
          corsHeaders
        );
      }

      return jsonResponse(
        { success: true, message: "Telegram notification sent successfully." },
        200,
        corsHeaders
      );
    } catch (err) {
      return jsonResponse(
        {
          success: false,
          error: "Authentication or processing failed.",
          message: err.message || "Unauthorized"
        },
        401,
        corsHeaders
      );
    }
  }
};

/**
 * Cryptographically verifies a Firebase ID Token using Web Crypto API & Google Public Certificates
 */
async function verifyFirebaseIdToken(token, projectId) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed JWT.");
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const header = JSON.parse(base64UrlDecodeToString(headerB64));
  const payload = JSON.parse(base64UrlDecodeToString(payloadB64));

  if (header.alg !== "RS256" || !header.kid) {
    throw new Error("Invalid JWT algorithm or missing key ID.");
  }

  const now = Math.floor(Date.now() / 1000);
  const expectedIssuer = `https://securetoken.google.com/${projectId}`;

  if (payload.aud !== projectId) {
    throw new Error("Invalid token audience.");
  }
  if (payload.iss !== expectedIssuer) {
    throw new Error("Invalid token issuer.");
  }
  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new Error("Firebase ID token has expired.");
  }
  if (typeof payload.iat !== "number" || payload.iat > now + 300) {
    throw new Error("Invalid token issued-at timestamp.");
  }
  if (!payload.sub || typeof payload.sub !== "string" || payload.sub.length > 128) {
    throw new Error("Invalid subject (UID) in token.");
  }

  // Fetch Google Public Keys (Cached automatically at Cloudflare Edge)
  const certsRes = await fetch(GOOGLE_CERTS_URL, {
    cf: { cacheTtl: 3600, cacheEverything: true }
  });
  if (!certsRes.ok) {
    throw new Error("Unable to fetch Google public certificates.");
  }

  const certs = await certsRes.json();
  const pemCert = certs[header.kid];
  if (!pemCert) {
    throw new Error("Public key matching token kid not found.");
  }

  const publicKey = await importX509Certificate(pemCert);
  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signatureBytes = base64UrlToUint8Array(signatureB64);

  const isValidSignature = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signatureBytes,
    signedData
  );

  if (!isValidSignature) {
    throw new Error("Invalid JWT cryptographic signature.");
  }

  return {
    uid: payload.sub,
    email: payload.email || null
  };
}

/**
 * Extracts SubjectPublicKeyInfo (SPKI) from an X.509 PEM certificate and imports it into Web Crypto
 */
async function importX509Certificate(pem) {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const spki = extractSpkiFromX509(der);

  return crypto.subtle.importKey(
    "spki",
    spki,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

/**
 * Minimal ASN.1 DER parser to locate SubjectPublicKeyInfo inside an X.509 Certificate
 */
function extractSpkiFromX509(der) {
  function readElement(buf, offset) {
    const tag = buf[offset];
    let lenByte = buf[offset + 1];
    let length = 0;
    let headerLen = 2;

    if (lenByte & 0x80) {
      const numBytes = lenByte & 0x7f;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | buf[offset + 2 + i];
      }
      headerLen += numBytes;
    } else {
      length = lenByte;
    }

    return {
      tag,
      headerLen,
      length,
      totalLen: headerLen + length,
      valueStart: offset + headerLen
    };
  }

  // Certificate SEQUENCE -> TBSCertificate SEQUENCE
  const certSeq = readElement(der, 0);
  const tbsSeq = readElement(der, certSeq.valueStart);
  let cursor = tbsSeq.valueStart;

  // Optional [0] version
  if (der[cursor] === 0xa0) {
    cursor += readElement(der, cursor).totalLen;
  }
  // serialNumber, signature, issuer, validity, subject (5 ASN.1 elements)
  for (let i = 0; i < 5; i++) {
    cursor += readElement(der, cursor).totalLen;
  }

  // 6th element is SubjectPublicKeyInfo SEQUENCE
  const spkiEl = readElement(der, cursor);
  return der.slice(cursor, cursor + spkiEl.totalLen).buffer;
}

function base64UrlDecodeToString(b64Url) {
  const bytes = base64UrlToUint8Array(b64Url);
  return new TextDecoder().decode(bytes);
}

function base64UrlToUint8Array(b64Url) {
  const b64 = b64Url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function buildCorsHeaders(origin) {
  const allowOrigin = ALLOWED_ORIGINS.includes(origin)
    ? origin
    : "https://reseller.ghotimarket.com";

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function jsonResponse(data, status, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });
}
