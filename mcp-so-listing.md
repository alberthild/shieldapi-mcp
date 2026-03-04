## Security intelligence for AI agents

ShieldAPI provides 9 security tools via MCP — from password breach checks to prompt injection detection. All tools work in **free demo mode** out of the box. Paid mode uses x402 USDC micropayments on Base.

### Tools

| Tool | What it does | Price |
|---|---|---|
| `check_password` | SHA-1 hash against 900M+ breached passwords (HIBP) | $0.001 |
| `check_password_range` | k-Anonymity password range lookup | $0.001 |
| `check_email` | Email breach exposure via HIBP | $0.005 |
| `check_domain` | DNS, SPF/DMARC, SSL, blacklist reputation | $0.003 |
| `check_ip` | Blacklists, Tor exit detection, reverse DNS | $0.002 |
| `check_url` | Phishing, malware, brand impersonation | $0.003 |
| `full_scan` | All checks combined in one call | $0.010 |
| **`check_prompt`** | Prompt injection detection — 200+ patterns, <100ms | $0.005 |
| **`scan_skill`** | AI skill/plugin supply chain scanner — 8 risk categories | $0.020 |

### Quick Start

```bash
npx shieldapi-mcp
```

All tools work immediately in demo mode — no wallet, no API key needed.

### Highlights

- **Prompt Injection Detection:** 200+ patterns including Base64, ROT13, Unicode homoglyphs, DAN/jailbreak, exfiltration attempts
- **Skill Supply Chain Security:** Scans for malicious code, credential leaks, suspicious downloads — based on Snyk ToxicSkills taxonomy
- **Real Breach Data:** 900M+ password hashes from Have I Been Pwned
- **x402 Native:** First security MCP server with pay-per-request USDC micropayments
- **No API Key:** Works out of the box in demo mode, add a wallet for paid mode

### Links

- [Live API](https://shield.vainplex.dev)
- [x402scan Listing](https://www.x402scan.com/server/55c99a38-34b3-4b2c-8987-f58ebd88a7df)
- [npm](https://www.npmjs.com/package/shieldapi-mcp)
- [GitHub](https://github.com/alberthild/shieldapi-mcp)
