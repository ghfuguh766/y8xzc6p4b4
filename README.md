# VPLink Proxy Hunter — Workflow Edition

Proxy discovery & verification pipeline deployed via GitHub Actions.

## One-liner install

```bash
curl -fsSL https://raw.githubusercontent.com/adittaya/workflow-proxy/main/install-proxy247.sh | bash
```

## Deployment Tool

```bash
python3 proxy247.py                # Interactive menu
python3 proxy247.py deploy new     # Deploy a new hunter
python3 proxy247.py deploy bulk N  # Bulk-deploy N hunters
```

## What's inside

- `proxy247.py` — The deployment manager (accounts, deploy, test, analytics)
- `vplink_hunter/` — 3-engine proxy scanner (scrape → test → verify → DB)
- `.github/workflows/hunt.yml` — GitHub Actions workflow for scheduled proxy hunting

## Requirements

- GitHub account + personal access token
- Supabase project with `proxy_results` table

## Quick start

```bash
python3 proxy247.py account add default --token ghp_xxxxx
python3 proxy247.py db config
python3 proxy247.py deploy new
```
