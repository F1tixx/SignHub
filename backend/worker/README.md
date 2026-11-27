# SignHub private signing broker

A Cloudflare Worker + D1 + private R2 broker for the SignHub web UI. Signing happens on a macOS GitHub Actions runner; no certificate, password or IPA is published as a GitHub artifact.

## Architecture

- The browser uploads IPA, P12 and MobileProvision directly to private R2 with 15-minute presigned PUT URLs.
- D1 stores an opaque job ID, HMAC hashes of the owner capability and client IP, state, a 24-hour expiry, declared upload sizes and the runner claim for the job.
- The P12 password and settings are AES-256-GCM encrypted in R2; the raw password is never stored in D1.
- A GitHub App dispatches the workflow; the app private key exists only as a Worker secret.
- Before claiming or finishing a job, the runner must present a GitHub OIDC token with the expected issuer, audience (`signhub-worker`), repository, ref and workflow identity. The token's `run_id`/`run_attempt` is bound to the job, so a different run cannot finish it.
- At completion, the broker checks that a non-empty signed IPA exists before marking the job done.
- Output stays in private R2. The owner capability protects status and manifest retrieval; the direct download URL is a one-hour bearer URL.
- A cron removes job objects and D1 rows after 24 hours. Per-IP throttle: three job creations per hour (IP is hashed before storage).

## Deploy Cloudflare resources

1. Create an R2 bucket named `signhub-private-jobs`.
2. Create a D1 database named `signhub-jobs`; copy its ID into `wrangler.toml`.
3. From `backend/worker`, run `npm install`, then `npm run db:migrate` and `npm run deploy`.
   The migration `0002_runner_claim.sql` adds the runner-binding column; apply both migrations on a new database.
4. Set Worker secrets (never commit these):
   - `R2_ACCOUNT_ID`
   - `R2_ACCESS_KEY_ID`
   - `R2_SECRET_ACCESS_KEY`
   - `GITHUB_APP_ID`
   - `GITHUB_APP_INSTALLATION_ID`
   - `GITHUB_APP_PRIVATE_KEY` (PEM private key, `\n` escapes are accepted)
   - `JOB_ENCRYPTION_KEY` (base64 of exactly 32 random bytes)
   - `OWNER_TOKEN_PEPPER` (long random secret)
5. Set `ALLOWED_ORIGIN`, `GITHUB_REPOSITORY`, `GITHUB_REF` and `R2_BUCKET` in `wrangler.toml`. The origin must exactly match the secure frontend origin.
6. Configure R2 bucket CORS to allow `PUT` from that origin and allow the `Content-Type` request header.
7. In the fork's GitHub settings, add an Actions variable `SIGNHUB_BROKER_URL` equal to the Worker URL.
8. In the root `broker-config.js`, set `window.SIGNHUB_BROKER_URL` to the same URL.

The worker returns `503 Service is not configured` until placeholder values are replaced.

## GitHub App

Install a GitHub App on this fork with repository **Actions: read/write** and **Metadata: read**. Store its private key only as the Worker secret `GITHUB_APP_PRIVATE_KEY`. Do not grant broader permissions.

## API

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/v1/jobs` | browser origin | Create a job and receive presigned PUT URLs |
| `PUT` | presigned R2 URL | presigned URL | Upload one declared file |
| `POST` | `/v1/jobs/:id/complete` | owner token | Verify uploads, store encrypted metadata, dispatch workflow |
| `GET` | `/v1/jobs/:id/status` | owner token | Poll state, error and final links |
| `GET` | `/v1/jobs/:id/manifest?token=...` | owner token | OTA plist for iOS |
| `POST` | `/internal/claim` | runner OIDC | Bind and claim a queued job |
| `POST` | `/internal/finish` | runner OIDC | Report done/failed for the claimed run |

Only the `ipa`, `p12` and `profile` slots are accepted. Client-supplied content types are ignored; the broker signs fixed `application/octet-stream` PUT URLs. Uploaded object sizes are verified against the declarations at completion.

## Frontend hosting

The fork's Pages workflow publishes the static UI at `https://f1tixx.github.io/SignHub/`. For that origin set `ALLOWED_ORIGIN = https://f1tixx.github.io` and allow `PUT` + `Content-Type` from it in R2 CORS. GitHub's guidance warns against sensitive transactions on GitHub Pages, so use Cloudflare Pages or another HTTPS host you control for public launch.

## Tests

```bash
npm install
npm test
```

Tests use Node's built-in runner and local stubs for D1, S3 and GitHub dispatch. They do not call GitHub or Cloudflare and do not sign an IPA.

## Limitations / pre-launch checklist

- Test with a non-production certificate and IPA before accepting real user material; automated tests cannot prove an iOS install works.
- Add Cloudflare edge rate limits and Turnstile/CAPTCHA before opening anonymous public intake. The hashed-IP throttle is not full abuse prevention.
- Verify the pinned Zsign version against your IPA/certificate combination.
- Check the OTA install flow on a real device; the manifest capability URL is not account-authenticated.
- Keep `main` protected and require review for workflow/Worker changes. Never run untrusted pull-request code with production credentials.
