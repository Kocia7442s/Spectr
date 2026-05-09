# Spectr — OSINT Domain Reconnaissance

Vanilla JS + native PHP + PostgreSQL. No framework, no Composer.

## Layout

```
api/         PHP endpoints, one per module
  _bootstrap.php   shared CORS / JSON / PDO / domain validation
  dns.php          A/AAAA/MX/TXT/NS/CNAME/SOA via dns_get_record()
  whois.php        socket WHOIS (IANA → registry → registrar chain)
  subdomains.php   crt.sh certificate-transparency ingestion
  headers.php      HTTP headers + tech fingerprint + security audit
  history.php      recent scans from PostgreSQL
config/      config.php (DB credentials, HTTP defaults)
db/          schema.sql (single `scans` table, JSONB result column)
frontend/    index.html — single-file vanilla JS dashboard
```

## Setup

```bash
# 1. PostgreSQL
createdb spectr
psql -d spectr -f db/schema.sql

# 2. Configure (or use env vars)
$EDITOR config/config.php
# or:
export SPECTR_DB_USER=spectr SPECTR_DB_PASS=spectr SPECTR_DB_NAME=spectr

# 3. Serve
php -S 127.0.0.1:8080
# Open http://127.0.0.1:8080/frontend/
```

## API

All endpoints accept `?domain=example.com` (GET) or JSON `{"domain":"…"}` (POST), return:

```json
{ "success": true,  "domain": "example.com", "data": { … } }
{ "success": false, "error":  "Invalid domain name." }
```

CORS is open (`Access-Control-Allow-Origin: *`). Each successful scan is persisted to `scans` as JSONB.

## Notes

- DNS suppresses `dns_get_record()` warnings per type so a single failing record doesn't kill the whole lookup.
- WHOIS first asks IANA for the TLD's registry, then queries the registry, then chases one registrar referral — covers thin registries like `.com`.
- `crt.sh` returns one row per certificate; subdomains are deduped, sorted, and split from wildcards.
- Headers module uses a 2 KB ranged GET (HEAD often returns 405) for body-based tech hints, then audits 8 standard security headers.
- DB unavailability never blocks an API response — `spectr_log_scan()` swallows its own errors.
