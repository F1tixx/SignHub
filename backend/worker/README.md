# SignHub secure broker (deployment scaffold)

This folder contains the Cloudflare Worker broker. It is not live until the Cloudflare resources and secrets below are configured.

## Resources
- Cloudflare Worker: `signhub-broker`
- D1 database: `signhub-jobs` (apply `migrations/0001_jobs.sql`)
- R2 bucket: `signhub-private-jobs`
- GitHub App installed on `suleyman13900/SignHub` with **Actions: read/write** and **Metadata: read** permissions.

## Required Worker secrets
Set with `wrangler secret put NAME` (never commit values):
- `R2_ACCOUNT_ID`
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `GITHUB_APP_PRIVATE_KEY` (PEM)
- `JOB_ENCRYPTION_KEY` (base64-encoded 32 random bytes)
- `OWNER_TOKEN_PEPPER` (long random value)

Set the non-secret values in `wrangler.toml`: D1 database id, GitHub App id and installation id, allowed website origin, repository and ref. Configure R2 bucket CORS to allow PUT from the GitHub Pages origin and the deployed Worker origin, with Content-Type allowed.

## GitHub repository configuration
Add repository variable `SIGNHUB_BROKER_URL` with the deployed Worker URL. The workflow uses GitHub OIDC; it does not need a PAT. The GitHub App private key stays in the Worker.

## Security model
- Each job receives a random owner capability; only its hash is stored in D1.
- Browser uploads go directly to R2 using short-lived presigned URLs; the Worker never proxies multi-gigabyte IPA bodies.
- P12 password and job settings are encrypted with AES-GCM before being stored in R2.
- A runner must present a GitHub OIDC token with the expected repository, ref, audience and workflow identity before it can claim or complete a job.
- Inputs and outputs are under per-job random object keys. The scheduled cleanup removes job objects and database rows after 24 hours.
- The result URL is a time-limited bearer URL. Anyone who receives that URL can access it until it expires; do not post it publicly.

## Important implementation notes
The current `signer.html` still targets the legacy NexSideloading API. Do not enter real certificates until the frontend is switched to this broker and the Worker has been deployed. The signing workflow currently implements the IPA + P12 + provisioning-profile Zsign path. Existing UI options for built-in apps and tweak injection require their own trusted asset/injection implementation and are not silently executed by this workflow. Direct IPA URL support also needs a separate SSRF-safe fetch stage before it can be enabled.
