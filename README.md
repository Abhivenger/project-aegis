@'
# Project Aegis

Real-time secret leak detection, live GitHub repository auditing, and pre-commit defense built with Next.js 15, TypeScript, and Python.

## Core Capabilities

- **Live GitHub Repository Auditor (`/dashboard`)** — Streams repository trees via the GitHub REST API, prioritizes high-risk configuration files, and scores repositories using calibrated Shannon entropy (`H >= 4.55`) and signature rules without flagging `.env.example` templates.
- **Code & Entropy Sandbox (`/dashboard/code-auditor`)** — Scans source snippets for exposed API keys, private keys, and high-entropy credentials, generating side-by-side diffs and sanitized `.env` templates.
- **SafeLink URL Inspector (`/dashboard/url-inspector`)** — Detects phishing links, Punycode/IDN homograph spoofs, and suspicious redirect chains.
- **Zero-Knowledge Secrets Vault (`/dashboard/vault`)** — Tracks credential rotation health and environment secret hygiene.
- **GitShield CLI Pre-Commit Defense (`cli/aegis.py`)** — Local Git hook that intercepts staged files and blocks unencrypted secrets before `git commit` leaves the workstation.

## Architecture

- **Frontend:** Next.js 15 (App Router), React, TypeScript, Tailwind CSS
- **Detection Engine:** Deterministic Shannon entropy analysis (`lib/scanners/entropy.ts`) + signature matching (`lib/scanners/code-analysis.ts`)
- **Local CLI Hook:** Python pre-commit scanner (`cli/aegis.py`)

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure environment variables
cp .env.example .env.local
# Add GITHUB_TOKEN in .env.local for higher GitHub API rate limits

# 3. Run in development or production mode
npm run dev
# or
npm run build && npm run start
