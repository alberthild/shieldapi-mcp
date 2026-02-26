# ShieldAPI MCP Server

Security intelligence tools for AI agents — check URLs, domains, IPs, emails, and passwords for threats. Pay-per-request with USDC micropayments via [x402](https://www.x402.org/), or use free demo mode.

## Quick Start

```bash
npx shieldapi-mcp
```

That's it. Without a wallet configured, it runs in **demo mode** (free sample data).

## Setup for Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "shieldapi": {
      "command": "npx",
      "args": ["-y", "shieldapi-mcp"],
      "env": {
        "SHIELDAPI_WALLET_PRIVATE_KEY": "0x..."
      }
    }
  }
}
```

## Setup for Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "shieldapi": {
      "command": "npx",
      "args": ["-y", "shieldapi-mcp"],
      "env": {
        "SHIELDAPI_WALLET_PRIVATE_KEY": "0x..."
      }
    }
  }
}
```

## Tools

| Tool | Description | Price |
|------|-------------|-------|
| `check_url` | Check URL for malware, phishing (URLhaus + heuristics) | $0.003 |
| `check_password` | Check SHA-1 hash against HIBP breach database | $0.001 |
| `check_password_range` | HIBP k-Anonymity prefix lookup | $0.001 |
| `check_domain` | Domain reputation (DNS, blacklists, SPF/DMARC, SSL) | $0.003 |
| `check_ip` | IP reputation (blacklists, Tor exit, reverse DNS) | $0.002 |
| `check_email` | Email breach lookup via HIBP | $0.005 |
| `full_scan` | All checks combined on a single target | $0.01 |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SHIELDAPI_URL` | `https://shield.vainplex.dev` | API base URL |
| `SHIELDAPI_WALLET_PRIVATE_KEY` | *(none)* | EVM private key for USDC payments. If not set, uses free demo mode. |
| `SHIELDAPI_NETWORK` | `base` | Network for payments (Base mainnet) |

## Demo Mode

Without `SHIELDAPI_WALLET_PRIVATE_KEY`, all tools return sample data for free. Great for testing your agent integration before configuring payments.

## How Payments Work

ShieldAPI uses [x402](https://www.x402.org/) — an open standard for HTTP-native micropayments:

1. Your agent calls a tool (e.g. `check_url`)
2. ShieldAPI responds with HTTP 402 + payment details
3. The MCP server automatically pays with USDC on Base
4. ShieldAPI returns the security data

You need USDC on Base in your wallet. Typical cost: $0.001–$0.01 per request.

## License

MIT

## Links

- **API**: https://shield.vainplex.dev
- **Docs**: https://shield.vainplex.dev/api/health
- **Source**: https://github.com/alberthild/shieldapi-mcp
