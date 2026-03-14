# Contributing to HTSBP

Thank you for your interest in contributing to **Has This Site Been Poisoned?**

## Ways to Contribute

### Report a Suspected IDPI Site

If you've discovered a website containing hidden prompt injection targeting AI agents:

1. Go to [New Issue](https://github.com/YOUR_USERNAME/htsbp/issues/new?template=new-threat.yml)
2. Fill in the URL, estimated severity, and what you observed
3. Our team will review and verify the report

### Add New Collectors

We welcome new data source integrations:

1. Fork the repository
2. Create a new collector in `src/collectors/`
3. Follow the pattern established in existing collectors (see `common.ts`)
4. Submit a pull request

### Improve Detection Heuristics

The web crawler (`src/collectors/web-crawler.ts`) uses pattern matching to detect IDPI payloads. Help us improve:

- Add new detection patterns for emerging techniques
- Reduce false positives
- Improve HTML parsing accuracy

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/htsbp.git
cd htsbp
npm install
npm run seed
npm run dev
```

## Code Style

- TypeScript strict mode
- JSDoc comments on all exports (English)
- JSON files: pretty print, alphabetically sorted keys

## Pull Request Process

1. Ensure TypeScript compiles without errors (`npx tsc --noEmit`)
2. Test your changes locally with `npm run dev`
3. Write a clear PR description explaining what and why
4. One focused change per PR

## Code of Conduct

Be respectful and constructive. We're all working toward the same goal: protecting AI agents from weaponized websites.
