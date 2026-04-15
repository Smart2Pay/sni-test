# Nuvei Akamai SNI & Cipher Suite Compatibility Tester

A zero-dependency Node.js script to verify that your system supports the upcoming Nuvei TLS/SSL certificate changes (SNI-only certificates and modern cipher suites).

## Background

Starting **May 1, 2026**, Nuvei is migrating all public TLS/SSL certificates to an SNI-only configuration and removing legacy cipher suites. The sandbox/integration environments have been updated since **April 1, 2026** for early testing.

This script tests:

1. **SNI connectivity** — verifies your system sends the SNI hostname during TLS handshake
2. **Non-SNI rejection** — confirms the server rejects connections without SNI (where enforced)
3. **TLS 1.3 cipher suites** — tests all 5 supported TLS 1.3 ciphers
4. **TLS 1.2 cipher suites** — tests all supported TLS 1.2 AEAD ciphers
5. **HTTPS end-to-end** — validates full HTTPS connectivity
6. **TLS version negotiation** — confirms TLS 1.2/1.3 work and TLS 1.0/1.1 are rejected

## Requirements

- **Node.js 14+** (no external dependencies — uses built-in `tls` and `https` modules)

## Usage

1. Clone this repository:

```bash
git clone https://github.com/Smart2Pay/sni-test.git
cd sni-test
```

2. Edit `test-sni-ciphers.js` and set the `ENDPOINTS` array to include the sandbox domains relevant to your integration:

```javascript
const ENDPOINTS = [
  "apitest.smart2pay.com",      // APM HTTP POST API (sandbox)
  "paytest.smart2pay.com",      // APM REST API (sandbox)
  "securetest.smart2pay.com",   // Credit Cards (sandbox)
];
```

3. Run the test:

```bash
node test-sni-ciphers.js
```

Or using npm:

```bash
npm test
```

## Endpoints Reference

| Product | Sandbox | Production |
|---------|---------|------------|
| APM HTTP POST API | `apitest.smart2pay.com` | `globalapi.smart2pay.com` |
| APM REST API | `paytest.smart2pay.com` | `globalpay.smart2pay.com` |
| Credit Cards | `securetest.smart2pay.com` | `secure.smart2pay.com` |

## Reading the Output

- **PASS** — test succeeded, your system is compatible
- **WARN** — connection succeeded but SNI-only is not yet enforced on this endpoint (it will be by May 1, 2026)
- **FAIL** — test failed; review the details:
  - If SNI connection fails: your TLS library needs updating
  - If only legacy CBC ciphers fail (e.g., `ECDHE-RSA-AES256-SHA`): this is **expected** — these ciphers are being deprecated and are not needed

## Supported Cipher Suites After Migration

### TLS 1.3

| Cipher Suite | Status |
|---|---|
| TLS_AES_256_GCM_SHA384 | Supported |
| TLS_CHACHA20_POLY1305_SHA256 | Supported |
| TLS_AES_128_GCM_SHA256 | Supported |
| TLS_AES_128_CCM_8_SHA256 | Supported |
| TLS_AES_128_CCM_SHA256 | Supported |

### TLS 1.2

| Cipher Suite | Status |
|---|---|
| ECDHE-ECDSA-AES256-GCM-SHA384 | Supported |
| ECDHE-ECDSA-AES128-GCM-SHA256 | Supported |
| ECDHE-RSA-AES256-GCM-SHA384 | Supported |
| ECDHE-RSA-AES128-GCM-SHA256 | Supported |
| ECDHE-ECDSA-CHACHA20-POLY1305 | Supported |
| ECDHE-RSA-CHACHA20-POLY1305 | Supported |

### No Longer Supported

- TLS 1.0, TLS 1.1
- All CBC-mode cipher suites

## Important Dates

| Date | Milestone |
|------|-----------|
| April 1, 2026 | Sandbox/Integration environments updated |
| April 1 – April 30, 2026 | Testing period |
| May 1, 2026 | Production rollout |

## Support

If you encounter issues during testing, please contact Nuvei technical support.
