#!/usr/bin/env node

/**
 * Nuvei Akamai SNI & Cipher Suite Compatibility Tester
 *
 * Tests TLS connectivity with SNI and validates cipher suite support
 * against the new Akamai certificate configuration (effective April 1, 2026).
 */

const tls = require("tls");
const https = require("https");
const { URL } = require("url");

// --- Configuration ---

const ENDPOINTS = [
  // Sandbox / Integration environment domains
  "apitest.smart2pay.com",
  "paytest.smart2pay.com",
  "securetest.smart2pay.com",
];

// TLS 1.3 cipher suites (configured via cipherSuites option)
const TLS13_CIPHERS = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_128_CCM_8_SHA256",
  "TLS_AES_128_CCM_SHA256",
];

// TLS 1.2 cipher suites (configured via ciphers option)
const TLS12_CIPHERS = [
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-RSA-AES256-SHA384",
  "ECDHE-RSA-AES256-SHA",
  "ECDHE-RSA-AES128-SHA",
];

const TIMEOUT_MS = 10000;

// --- Helpers ---

const PASS = "\x1b[32m✓ PASS\x1b[0m";
const FAIL = "\x1b[31m✗ FAIL\x1b[0m";
const WARN = "\x1b[33m⚠ WARN\x1b[0m";
const BOLD = (s) => `\x1b[1m${s}\x1b[0m`;
const DIM = (s) => `\x1b[2m${s}\x1b[0m`;

function banner(title) {
  const line = "═".repeat(60);
  console.log(`\n\x1b[36m${line}\x1b[0m`);
  console.log(`  ${BOLD(title)}`);
  console.log(`\x1b[36m${line}\x1b[0m\n`);
}

function sectionHeader(title) {
  console.log(`\n  ${BOLD(title)}`);
  console.log(`  ${"─".repeat(50)}`);
}

/**
 * Open a TLS connection with specific options and return connection details.
 */
function tlsConnect(host, port, options = {}) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      port,
      host,
      {
        servername: host, // SNI
        rejectUnauthorized: true,
        timeout: TIMEOUT_MS,
        ...options,
      },
      () => {
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();
        const cert = socket.getPeerCertificate();
        socket.end();
        resolve({ cipher, protocol, cert, authorized: socket.authorized });
      }
    );

    socket.on("error", (err) => {
      socket.destroy();
      reject(err);
    });

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("Connection timed out"));
    });
  });
}

/**
 * Test that SNI works — connect without SNI and with SNI, compare behavior.
 */
async function testSNI(host) {
  const results = { host, withSNI: null, withoutSNI: null };

  // With SNI (normal)
  try {
    const info = await tlsConnect(host, 443);
    results.withSNI = {
      success: true,
      protocol: info.protocol,
      cipher: info.cipher.name,
      certSubject: info.cert.subject?.CN || info.cert.subject?.O || "N/A",
      certIssuer: info.cert.issuer?.O || "N/A",
      validTo: info.cert.valid_to,
      authorized: info.authorized,
      subjectAltNames: info.cert.subjectaltname || "N/A",
    };
  } catch (err) {
    results.withSNI = { success: false, error: err.message };
  }

  // Without SNI — set servername to empty string
  try {
    const info = await tlsConnect(host, 443, { servername: "" });
    results.withoutSNI = {
      success: true,
      protocol: info.protocol,
      certSubject: info.cert.subject?.CN || info.cert.subject?.O || "N/A",
    };
  } catch (err) {
    results.withoutSNI = { success: false, error: err.message };
  }

  return results;
}

/**
 * Test a single cipher suite against a host.
 */
async function testCipher(host, cipher, isTLS13) {
  try {
    const opts = isTLS13
      ? { ciphers: "DEFAULT", cipherSuites: cipher, minVersion: "TLSv1.3", maxVersion: "TLSv1.3" }
      : { ciphers: cipher, maxVersion: "TLSv1.2" };

    const info = await tlsConnect(host, 443, opts);
    return {
      cipher,
      success: true,
      negotiated: info.cipher.name,
      protocol: info.protocol,
    };
  } catch (err) {
    return {
      cipher,
      success: false,
      error: err.message.includes("no ciphers")
        ? "Not supported by client"
        : err.message.includes("handshake")
        ? "Server rejected"
        : err.message,
    };
  }
}

/**
 * Make an HTTPS GET request to validate end-to-end connectivity.
 */
function httpsGet(host, path = "/") {
  return new Promise((resolve, reject) => {
    const req = https.get(
      { hostname: host, port: 443, path, timeout: TIMEOUT_MS },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () =>
          resolve({ statusCode: res.statusCode, headers: res.headers, bodyLength: body.length })
        );
      }
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });
  });
}

// --- Main ---

async function main() {
  const nodeVersion = process.version;
  const opensslVersion = process.versions.openssl;

  banner("Nuvei Akamai SNI & Cipher Suite Compatibility Test");

  console.log(`  Node.js:  ${nodeVersion}`);
  console.log(`  OpenSSL:  ${opensslVersion}`);
  console.log(`  Date:     ${new Date().toISOString()}`);

  let totalPass = 0;
  let totalFail = 0;
  let totalWarn = 0;

  // ── 1. SNI Connectivity Tests ──

  banner("1. SNI Connectivity Tests");

  for (const host of ENDPOINTS) {
    sectionHeader(host);

    const result = await testSNI(host);

    if (result.withSNI.success) {
      console.log(`  ${PASS}  SNI connection successful`);
      console.log(`         Protocol:    ${result.withSNI.protocol}`);
      console.log(`         Cipher:      ${result.withSNI.cipher}`);
      console.log(`         Certificate: ${result.withSNI.certSubject}`);
      console.log(`         Issuer:      ${result.withSNI.certIssuer}`);
      console.log(`         Valid until: ${result.withSNI.validTo}`);
      console.log(`         Authorized:  ${result.withSNI.authorized}`);
      if (result.withSNI.subjectAltNames !== "N/A") {
        const sans = result.withSNI.subjectAltNames.split(",").slice(0, 5).join(", ");
        console.log(`         SANs:        ${sans}...`);
      }
      totalPass++;
    } else {
      console.log(`  ${FAIL}  SNI connection failed: ${result.withSNI.error}`);
      totalFail++;
    }

    // Report what happens without SNI
    if (result.withoutSNI.success) {
      console.log(`  ${WARN}  Non-SNI connection also succeeded ${DIM("(will stop working after migration)")}`);
      totalWarn++;
    } else {
      console.log(`  ${PASS}  Non-SNI correctly rejected: ${DIM(result.withoutSNI.error)}`);
      totalPass++;
    }
  }

  // ── 2. TLS 1.3 Cipher Suite Tests ──

  banner("2. TLS 1.3 Cipher Suite Tests");

  const cipherTestHost = ENDPOINTS[0]; // use first endpoint for cipher tests
  console.log(`  ${DIM(`Testing against: ${cipherTestHost}`)}\n`);

  for (const cipher of TLS13_CIPHERS) {
    const result = await testCipher(cipherTestHost, cipher, true);
    if (result.success) {
      console.log(`  ${PASS}  ${cipher}  ${DIM(`→ ${result.protocol}`)}`);
      totalPass++;
    } else {
      console.log(`  ${FAIL}  ${cipher}  ${DIM(`→ ${result.error}`)}`);
      totalFail++;
    }
  }

  // ── 3. TLS 1.2 Cipher Suite Tests ──

  banner("3. TLS 1.2 Cipher Suite Tests");
  console.log(`  ${DIM(`Testing against: ${cipherTestHost}`)}\n`);

  for (const cipher of TLS12_CIPHERS) {
    const result = await testCipher(cipherTestHost, cipher, false);
    if (result.success) {
      console.log(`  ${PASS}  ${cipher}  ${DIM(`→ ${result.protocol}`)}`);
      totalPass++;
    } else {
      console.log(`  ${FAIL}  ${cipher}  ${DIM(`→ ${result.error}`)}`);
      totalFail++;
    }
  }

  // ── 4. HTTPS End-to-End Test ──

  banner("4. HTTPS End-to-End Connectivity");

  for (const host of ENDPOINTS) {
    try {
      const res = await httpsGet(host);
      console.log(`  ${PASS}  ${host}  ${DIM(`→ HTTP ${res.statusCode}`)}`);
      totalPass++;
    } catch (err) {
      console.log(`  ${FAIL}  ${host}  ${DIM(`→ ${err.message}`)}`);
      totalFail++;
    }
  }

  // ── 5. TLS Version Support ──

  banner("5. TLS Version Negotiation");
  console.log(`  ${DIM(`Testing against: ${cipherTestHost}`)}\n`);

  for (const ver of ["TLSv1.3", "TLSv1.2"]) {
    try {
      const info = await tlsConnect(cipherTestHost, 443, {
        minVersion: ver,
        maxVersion: ver,
      });
      console.log(`  ${PASS}  ${ver} supported  ${DIM(`→ cipher: ${info.cipher.name}`)}`);
      totalPass++;
    } catch (err) {
      console.log(`  ${FAIL}  ${ver} not supported  ${DIM(`→ ${err.message}`)}`);
      totalFail++;
    }
  }

  // Legacy versions should be rejected
  for (const ver of ["TLSv1.1", "TLSv1"]) {
    try {
      const info = await tlsConnect(cipherTestHost, 443, {
        minVersion: ver,
        maxVersion: ver,
      });
      console.log(`  ${WARN}  ${ver} still accepted ${DIM("(should be disabled)")}`);
      totalWarn++;
    } catch {
      console.log(`  ${PASS}  ${ver} correctly rejected`);
      totalPass++;
    }
  }

  // ── Summary ──

  banner("Summary");

  console.log(`  ${PASS}  Passed:   ${totalPass}`);
  if (totalWarn > 0) console.log(`  ${WARN}  Warnings: ${totalWarn}`);
  if (totalFail > 0) console.log(`  ${FAIL}  Failed:   ${totalFail}`);
  console.log();

  if (totalFail === 0) {
    console.log("  \x1b[32m🎉 All critical tests passed. Your system is compatible.\x1b[0m\n");
  } else {
    console.log("  \x1b[31m⚠  Some tests failed. Review the results above.\x1b[0m\n");
  }

  process.exit(totalFail > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(2);
});
