# SignHub private signing broker

This is a deployable Cloudflare Worker + D1 + private R2 broker. The repository now includes a frontend integration and GitHub Actions workflow, but the service is **not live** until the Cloudflare resources, GitHub App and secrets are configured.

## Architecture and privacy
- Browser uploads IPA, P12 and MobileProvision directly to private R2 using 15-minute presigned PUT URLs.
- D1 stores an opaque job ID, a hash of the owner capability, a hash of the client IP for throttling, state and a 24-hour expiry.
- The P12 password and settings are AES-256-GCM encrypted in R2. The raw password is not stored in D1.
- A GitHub App dispatches the workflow; no personal access token is placed in the browser or repository.
- A macOS Actions runner must present a GitHub OIDC token with the expected issuer, audience, repository, ref and workflow identity before it can claim or complete a job.
- Output is stored in private R2. The owner capability protects status and manifest retrieval; the download URL is a one-hour bearer URL. Anyone who receives a valid link can use it until it expires.
- The scheduled cleanup removes job objects and D1 rows after 24 hours. Per-IP throttle: three job creations per hour (IP is hashed before storage).

## Deploy Cloudflare resources
1. Create an R2 bucket named `signhub-private-jobs`.
2. Create a D1 database named `signhub-jobs`; copy its database ID into `wrangler.toml`.
3. From `backend/worker`, run `npm install`, then `npx wrangler d1 migrations apply signhub-jobs --remote` and `npx wrangler deploy`.
4. Set Worker secrets (never commit these):
   - `R2_ACCOUNT_ID`
   - `R2_ACCESS_KEY_ID`
   - `R2_SECRET_ACCESS_KEY`
   - `GITHUB_APP_PRIVATE_KEY` (PEM private key)
   - `JOB_ENCRYPTION_KEY` (base64 for exactly 32 random bytes)
   - `OWNER_TOKEN_PEPPER` (long random secret)
5. Set `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, `R2_BUCKET`, `GITHUB_REPOSITORY`, `GITHUB_REF`, and `ALLOWED_ORIGIN` in `wrangler.toml`. The allowed origin must exactly match the secure frontend origin.
6. Configure R2 bucket CORS to allow `PUT` from the secure frontend origin and allow the `Content-Type` request header.
7. In GitHub repository settings, add Actions variable `SIGNHUB_BROKER_URL` equal to the Worker URL.

## GitHub App
Install a GitHub App on this repository with repository **Actions: read/write** and **Metadata: read**. Store its private key only as the Worker secret `GITHUB_APP_PRIVATE_KEY`. Do not give the app broader permissions than needed.

## Frontend
Set `window.SIGNHUB_BROKER_URL` in the root `broker-config.js` to the deployed Worker URL. The existing SignHub layout is retained. The first secure path accepts local IPA/P12/profile uploads; direct URL imports, built-in app presets and tweak injection are intentionally rejected until their backend support is implemented safely.

**Hosting note:** GitHub's Pages guidance says Pages should not be used for sensitive transactions such as sending passwords. For public launch, serve the existing static UI from Cloudflare Pages or another HTTPS host under your control, then set `ALLOWED_ORIGIN` and R2 CORS to that origin. Keep GitHub Pages as a source/demo page if desired.

## Signing workflow
`.github/workflows/signhub-sign.yml` runs on `macos-14`, checks the runner's GitHub OIDC identity through the Worker, downloads only that job's files, signs with Zsign, uploads the IPA to private R2 and reports completion. The workflow does not publish certificates, passwords, IPA files or artifacts to GitHub.

## Current limitations / pre-launch checklist
- Test with a non-production certificate and test IPA before accepting real user material.
- Validate the exact Zsign version and command behavior against your own IPA/certificate combination.
- Configure Cloudflare edge rate limits and Turnstile/CAPTCHA before opening anonymous public intake to the internet. The Worker has a basic hashed-IP job creation throttle, not a full abuse-prevention system.
- Verify the iOS OTA install flow on a real device. The manifest endpoint is a short-lived bearer capability URL, not account-authenticated access.
- The current workflow implements IPA + P12 + provisioning profile only. URL fetching is deliberately disabled to avoid SSRF; tweak injection and built-in app handling remain disabled.
- Keep the main branch protected and require review for workflow/Worker changes. Do not run untrusted pull-request code with production credentials.
