# Has This Site Been Poisoned?

> Open-source threat intelligence for AI agents — the first database of websites weaponized with indirect prompt injection (IDPI).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What is IDPI?

Indirect Prompt Injection (IDPI) is an attack where adversaries embed hidden instructions
in web content that AI agents unknowingly execute. OWASP ranks it as the #1 threat
to LLM applications (2025).

**HTSBP** is the first threat intelligence feed specifically targeting IDPI on the web.

## Quick Start

### REST API
```bash
curl "https://hasthissitebeenpoisoned.ai/api/check-domain?domain=reviewerpress.com"
```

### MCP Server (Claude Desktop / Cursor / Windsurf)
```json
{
  "mcpServers": {
    "htsbp": {
      "url": "https://hasthissitebeenpoisoned.ai/api/mcp"
    }
  }
}
```

### Raw Data
All threat data is available as JSON files in [`data/threats/`](data/threats/).

## Architecture

No database. No backend state. All threat data lives as JSON files in this repository.

- **Data collection**: GitHub Actions runs daily, collecting from Unit42, OTX, and AI-driven crawling (OpenClaw with web search)
- **Data storage**: JSON files in `data/` — every change is a git commit with full history
- **API**: Netlify Functions reads JSON at build time
- **Analytics**: Netlify Analytics (server-side, zero JS)
- **Community reports**: via MCP `report_threat` tool, `POST /api/report-threat`, or GitHub Issues
- **Auto-verification**: Community reports are automatically scanned and registered if IDPI patterns are confirmed
- **Self-improving detection**: IDPI patterns in [`data/patterns.json`](data/patterns.json) are auto-updated by AI analysis

## Data Sources

| Source | Type | Frequency |
|--------|------|-----------|
| Unit 42 (Palo Alto Networks) | IoC feeds | Daily |
| AlienVault OTX | Discovery trigger (independently verified) | Daily |

| AI Web Crawler (Claude) | Active analysis | Daily |
| Community Reports | GitHub Issues | Continuous |

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md).

Ways to contribute:
- **AI agents**: Use `report_threat` MCP tool or `POST /api/report-threat` to report programmatically
- **Humans**: [Report a suspected IDPI site](https://github.com/tanbablack/htsbp/issues/new?template=new-threat.yml)
- Add new collectors
- Improve detection heuristics

## Self-Hosting

```bash
git clone https://github.com/tanbablack/htsbp.git
cd htsbp
npm install
npm run seed
npm run dev
```

## License

MIT
