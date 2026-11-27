# SignHub

A small web interface for signing and installing iOS applications with **your own** signing certificate.

This repository is a fork of [suleyman13900/SignHub](https://github.com/suleyman13900/SignHub), licensed under GPL-3.0. The original `LICENSE` is kept unchanged.

## What changed in this fork

- The signer talks only to a **self-hosted Cloudflare Worker broker**; it no longer sends certificates, IPAs or passwords to a third-party signing service.
- The broker verifies uploaded object sizes, binds each job to one GitHub Actions run, checks that the signed IPA exists before marking a job done, and returns generic internal errors.
- The signing workflow uses a pinned Zsign commit and always reports success or failure to the broker.
- Broker logic has automated tests with no extra runtime dependencies.
- URL imports, built-in apps and tweak injection remain disabled because the broker does not implement them safely.

## Flow

1. Open `signer.html` over HTTPS.
2. Choose an `.ipa`, `.p12` and `.mobileprovision` file, and provide the P12 password.
3. The browser creates a job and uploads the three files directly to private R2 using short-lived presigned URLs.
4. The worker encrypts the password and settings, then dispatches `signhub-sign.yml` on a macOS runner via a GitHub App.
5. The runner presents its OIDC identity, downloads only that job's files, signs with Zsign, uploads the signed IPA to private R2 and reports the result.
6. The browser polls job status and shows an `itms-services://` install link plus a direct download link.

## Requirements

- Cloudflare account with R2 and D1.
- A GitHub App installed on **this fork** with `Actions: read/write` and `Metadata: read`.
- A GitHub Actions macOS runner (`macos-15`).
- A secure HTTPS origin for the static site. GitHub Pages is fine for a demo, but use your own HTTPS host for real password submissions.
- Your own Apple signing certificate and provisioning profile.

## Deploy

1. Create an R2 bucket (`signhub-private-jobs`) and a D1 database (`signhub-jobs`). Put the D1 database ID in `backend/worker/wrangler.toml`.
2. From `backend/worker`, run `npm install`, `npm run db:migrate` and `npm run deploy`.
3. Set Worker secrets (never commit these):
   - `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`
   - `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID`, `GITHUB_APP_PRIVATE_KEY`
   - `JOB_ENCRYPTION_KEY` (base64 of exactly 32 random bytes)
   - `OWNER_TOKEN_PEPPER` (long random secret)
4. In `wrangler.toml`, replace `ALLOWED_ORIGIN`, `GITHUB_APP_ID` and `GITHUB_APP_INSTALLATION_ID`. `GITHUB_REPOSITORY` already points to `F1tixx/SignHub`.
5. Configure R2 CORS to allow `PUT` from the site origin and the `Content-Type` header.
6. Set `window.SIGNHUB_BROKER_URL` in `broker-config.js` to the deployed Worker URL.
7. Add an Actions variable `SIGNHUB_BROKER_URL` with the same Worker URL.
8. Protect the `main` branch and require review for changes to the worker or workflows.

See [backend/worker/README.md](backend/worker/README.md) for details and limitations.

## Development

Node 20 or newer is required.

```bash
cd backend/worker
npm install
npm test
```

`npm test` covers validation, ownership, rate limiting, upload-size checks, runner binding and manifest escaping. The macOS signing check also runs in CI.

## GitHub Pages demo

The static UI is deployed automatically to **https://f1tixx.github.io/SignHub/** by [`.github/workflows/pages.yml`](.github/workflows/pages.yml). This is fine for a UI smoke test, but use a host you control for real password submissions (GitHub's own guidance warns against sensitive transactions on Pages).

To test against your broker:

1. Deploy the worker and set `ALLOWED_ORIGIN = https://f1tixx.github.io`.
2. Allow `PUT` and the `Content-Type` header from that origin in R2 CORS.
3. Set `window.SIGNHUB_BROKER_URL` in `broker-config.js` to the worker URL and push to `main`; Pages redeploys automatically.
4. Open the Pages `signer.html` in a desktop browser. Until the broker is configured, the Console shows a configuration error instead of a network error.

## Smoke test before real use

1. Deploy the worker and configure every secret and variable above.
2. Run the `SignHub checks` workflow; both jobs must pass.
3. Sign a test IPA with a non-production certificate on a real iPhone in Safari.
4. Confirm the install link and the direct download both work, then confirm a job is cleaned up after 24 hours.

## Limits

- IPA 5 GB, P12 50 MB, provisioning profile 20 MB.
- Three job creations per hashed IP per hour; add Cloudflare rate limiting/Turnstile before anonymous public intake.
- Install links last 24 hours; direct download URLs last 1 hour.
- No URL imports, tweak injection or built-in apps.
- Live signing is **not** verified by the automated tests. Do not treat a passing test run as proof that an IPA installs on a device.

## Security note

Signing certificates contain private keys. The bundled certificate and DNS profiles are historical upstream assets; use certificates you are authorized to use. Never commit Worker secrets, P12 passwords or private keys.
