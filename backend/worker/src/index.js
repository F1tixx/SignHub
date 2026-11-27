import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, ListObjectsV2Command, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { SignJWT, importPKCS8, createRemoteJWKSet, jwtVerify } from "jose";

export const LIMITS = Object.freeze({ ipa: 5 * 1024 * 1024 * 1024, p12: 50 * 1024 * 1024, profile: 20 * 1024 * 1024 });
const SLOTS = Object.keys(LIMITS);
const CONTENT_TYPE = "application/octet-stream";
const PLACEHOLDERS = /YOUR-|SET_ME|SET_AFTER|example/i;

class ClientError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const cors = env => ({
  "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin",
  "X-Content-Type-Options": "nosniff"
});
const json = (data, status, env) => new Response(JSON.stringify(data), {
  status: status || 200,
  headers: { ...cors(env), "Content-Type": "application/json", "Cache-Control": "no-store" }
});
const fail = (message, status, env) => json({ error: message }, status, env);
const s3 = env => new S3Client({
  region: "auto",
  endpoint: `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY }
});
const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, "0")).join("");
const random = (n = 32) => {
  const b = crypto.getRandomValues(new Uint8Array(n));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const tokenKey = env => crypto.subtle.importKey(
  "raw", new TextEncoder().encode(env.OWNER_TOKEN_PEPPER),
  { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
);
const tokenHash = async (env, token) => hex(await crypto.subtle.sign("HMAC", await tokenKey(env), new TextEncoder().encode(token)));
const encryptionKey = async env => {
  const raw = Uint8Array.from(atob(env.JOB_ENCRYPTION_KEY), c => c.charCodeAt(0));
  if (raw.length !== 32) throw new Error("JOB_ENCRYPTION_KEY must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
};
async function encrypt(env, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await encryptionKey(env), new TextEncoder().encode(JSON.stringify(value)));
  return new Uint8Array([...iv, ...new Uint8Array(data)]);
}
async function decrypt(env, value) {
  const bytes = new Uint8Array(value);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: bytes.slice(0, 12) }, await encryptionKey(env), bytes.slice(12)
  );
  return JSON.parse(new TextDecoder().decode(plain));
}
async function signedPut(env, objectKey) {
  return getSignedUrl(s3(env), new PutObjectCommand({ Bucket: env.R2_BUCKET, Key: objectKey, ContentType: CONTENT_TYPE }), { expiresIn: 900 });
}
async function signedGet(env, objectKey, filename) {
  return getSignedUrl(s3(env), new GetObjectCommand({
    Bucket: env.R2_BUCKET, Key: objectKey, ResponseContentDisposition: `attachment; filename="${filename || "signed.ipa"}"`
  }), { expiresIn: 3600 });
}
async function readJson(request) {
  try { return await request.json(); } catch (_) { throw new ClientError("Invalid JSON body"); }
}
function configProblem(env) {
  const required = [
    "R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET",
    "GITHUB_APP_ID", "GITHUB_APP_INSTALLATION_ID", "GITHUB_APP_PRIVATE_KEY",
    "GITHUB_REPOSITORY", "ALLOWED_ORIGIN", "JOB_ENCRYPTION_KEY", "OWNER_TOKEN_PEPPER"
  ];
  for (const name of required) {
    const value = env[name];
    if (!value || PLACEHOLDERS.test(String(value))) return name;
  }
  return null;
}

export function validateFiles(files) {
  if (!Array.isArray(files) || files.length !== SLOTS.length) return null;
  const seen = new Set();
  for (const file of files) {
    if (!file || typeof file.slot !== "string" || !Object.hasOwn(LIMITS, file.slot) || seen.has(file.slot)) return null;
    if (!Number.isSafeInteger(file.size) || file.size < 1 || file.size > LIMITS[file.slot]) return null;
    seen.add(file.slot);
  }
  return seen.size === SLOTS.length ? files : null;
}

export function sanitizeSettings(value) {
  const out = {};
  if (!value || typeof value !== "object") return out;
  for (const key of ["bundle_id", "bundle_name", "bundle_version"]) {
    const raw = value[key];
    if (typeof raw !== "string") continue;
    const trimmed = raw.trim();
    if (trimmed && trimmed.length <= 128 && !/[\u0000-\u001f\u007f]/.test(trimmed)) out[key] = trimmed;
  }
  return out;
}

export function sanitizeAppInfo(value) {
  const out = {};
  if (!value || typeof value !== "object") return out;
  for (const key of ["bundle_id", "bundle_version", "bundle_name"]) {
    if (typeof value[key] === "string" && value[key].length <= 256) out[key] = value[key];
  }
  return out;
}

export function xmlEscape(value) {
  const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" };
  return String(value ?? "").replace(/[&<>"']/g, char => entities[char]);
}

export function runnerIdentity(payload) {
  return `${payload.repository}:${payload.run_id}:${payload.run_attempt || "1"}`;
}

async function appToken(env) {
  const pk = await importPKCS8(env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, "\n"), "RS256");
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({ iat: now - 30, exp: now + 540, iss: env.GITHUB_APP_ID })
    .setProtectedHeader({ alg: "RS256" }).sign(pk);
  const r = await fetch(`https://api.github.com/app/installations/${env.GITHUB_APP_INSTALLATION_ID}/access_tokens`, {
    method: "POST",
    headers: { Authorization: `Bearer ${assertion}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" },
    body: "{}"
  });
  if (!r.ok) throw new Error("Could not authorize GitHub App");
  return (await r.json()).token;
}

function fullRef(env) {
  const ref = env.GITHUB_REF || "refs/heads/main";
  return ref.startsWith("refs/") ? ref : `refs/heads/${ref}`;
}

async function dispatch(env, jobId) {
  const token = await appToken(env);
  const ref = fullRef(env).replace(/^refs\/(heads|tags)\//, "");
  const r = await fetch(`https://api.github.com/repos/${env.GITHUB_REPOSITORY}/actions/workflows/signhub-sign.yml/dispatches`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" },
    body: JSON.stringify({ ref, inputs: { job_id: jobId } })
  });
  if (!r.ok) throw new Error("GitHub workflow dispatch failed");
}

async function verifyRunner(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) throw new ClientError("Missing runner identity", 401);
  const jwks = createRemoteJWKSet(new URL("https://token.actions.githubusercontent.com/.well-known/jwks"));
  const { payload } = await jwtVerify(token, jwks, {
    issuer: "https://token.actions.githubusercontent.com", audience: "signhub-worker"
  });
  const repo = String(env.GITHUB_REPOSITORY || "").toLowerCase();
  const ref = fullRef(env);
  const workflow = `/.github/workflows/signhub-sign.yml@${ref}`.toLowerCase();
  if (!payload.run_id || String(payload.repository || "").toLowerCase() !== repo ||
      payload.ref !== ref || !String(payload.workflow_ref || "").toLowerCase().endsWith(workflow)) {
    throw new ClientError("Runner identity is not authorized", 403);
  }
  return payload;
}

async function assertUploaded(env, item, slot) {
  let head;
  try {
    head = await s3(env).send(new HeadObjectCommand({ Bucket: env.R2_BUCKET, Key: item.key }));
  } catch (_) {
    throw new ClientError("Uploaded file is missing or incomplete");
  }
  const size = Number(head.ContentLength);
  if (!Number.isSafeInteger(size) || size !== item.size || size < 1 || size > LIMITS[slot]) {
    throw new ClientError("Uploaded file size does not match the declaration");
  }
}

async function createJob(request, env) {
  const body = await readJson(request);
  const files = validateFiles(body.files);
  if (!files) throw new ClientError("Send exactly one ipa, p12 and profile, each with a valid size");

  const now = Math.floor(Date.now() / 1000);
  const ipHash = await tokenHash(env, request.headers.get("CF-Connecting-IP") || "unknown");
  const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM jobs WHERE client_hash=? AND created_at>?")
    .bind(ipHash, now - 3600).first();
  if ((recent?.n || 0) >= 3) throw new ClientError("Rate limit reached. Try again in an hour.", 429);

  const id = random(18), owner = random(32), expires = now + 86400;
  const uploads = {};
  for (const file of files) {
    const key = `jobs/${id}/input/${file.slot}`;
    uploads[file.slot] = { key, size: file.size, content_type: CONTENT_TYPE, url: await signedPut(env, key) };
  }
  await env.DB.prepare("INSERT INTO jobs (id, owner_hash, client_hash, state, created_at, expires_at, uploads_json) VALUES (?, ?, ?, 'uploading', ?, ?, ?)")
    .bind(id, await tokenHash(env, owner), ipHash, now, expires, JSON.stringify(uploads)).run();
  return json({ job_id: id, owner_token: owner, expires_at: expires, uploads }, 201, env);
}

async function completeJob(request, env, id) {
  const body = await readJson(request);
  const owner = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const row = await env.DB.prepare("SELECT * FROM jobs WHERE id=?").bind(id).first();
  if (!row || row.expires_at < Date.now() / 1000 || !owner || await tokenHash(env, owner) !== row.owner_hash) {
    throw new ClientError("Job not found", 404);
  }
  if (row.state !== "uploading") throw new ClientError("Job already submitted", 409);

  const uploads = JSON.parse(row.uploads_json);
  for (const slot of SLOTS) {
    if (!uploads[slot]) throw new ClientError("Required input missing");
    await assertUploaded(env, uploads[slot], slot);
  }
  if (typeof body.p12_password !== "string" || !body.p12_password || body.p12_password.length > 1024) {
    throw new ClientError("P12 password required");
  }

  const metadata = { password: body.p12_password, settings: sanitizeSettings(body.settings), uploads };
  await s3(env).send(new PutObjectCommand({
    Bucket: env.R2_BUCKET, Key: `jobs/${id}/metadata.enc`, Body: await encrypt(env, metadata), ContentType: CONTENT_TYPE
  }));
  const updated = await env.DB.prepare("UPDATE jobs SET state='queued' WHERE id=? AND state='uploading'").bind(id).run();
  if (!updated.meta?.changes) throw new ClientError("Job already submitted", 409);
  try {
    await dispatch(env, id);
  } catch (_) {
    await env.DB.prepare("UPDATE jobs SET state='failed', error=? WHERE id=?").bind("Could not queue signing job", id).run();
    throw new ClientError("Could not queue signing job", 502);
  }
  return json({ job_id: id, state: "queued", expires_at: row.expires_at }, 202, env);
}

async function jobStatus(request, env, id, url) {
  const owner = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  const row = await env.DB.prepare("SELECT * FROM jobs WHERE id=?").bind(id).first();
  if (!row || row.expires_at < Date.now() / 1000 || !owner || await tokenHash(env, owner) !== row.owner_hash) {
    throw new ClientError("Job not found", 404);
  }
  const result = {
    job_id: id, state: row.state, error: row.error || null, expires_at: row.expires_at,
    app_info: row.app_info_json ? JSON.parse(row.app_info_json) : null
  };
  if (row.state === "done") {
    result.download_url = await signedGet(env, `jobs/${id}/signed.ipa`, "signed.ipa");
    result.manifest_url = `${url.origin}/v1/jobs/${id}/manifest?token=${encodeURIComponent(owner)}`;
    result.install_url = `itms-services://?action=download-manifest&url=${encodeURIComponent(result.manifest_url)}`;
  }
  return json(result, 200, env);
}

async function jobManifest(env, id, url) {
  const owner = url.searchParams.get("token") || "";
  const row = await env.DB.prepare("SELECT * FROM jobs WHERE id=?").bind(id).first();
  if (!row || row.state !== "done" || row.expires_at < Date.now() / 1000 || !owner || await tokenHash(env, owner) !== row.owner_hash) {
    throw new ClientError("Manifest not found", 404);
  }
  const ipa = await signedGet(env, `jobs/${id}/signed.ipa`, "signed.ipa");
  const info = row.app_info_json ? JSON.parse(row.app_info_json) : {};
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${xmlEscape(ipa)}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${xmlEscape(info.bundle_id)}</string><key>bundle-version</key><string>${xmlEscape(info.bundle_version)}</string><key>kind</key><string>software</string><key>title</key><string>${xmlEscape(info.bundle_name || "Signed app")}</string></dict></dict></array></dict></plist>`;
  return new Response(plist, { headers: { ...cors(env), "Content-Type": "application/xml", "Cache-Control": "no-store" } });
}

export async function claimJob(request, env, identity) {
  const { job_id: jobId } = await readJson(request);
  if (typeof jobId !== "string" || !/^[A-Za-z0-9_-]+$/.test(jobId)) throw new ClientError("Invalid job ID");
  const row = await env.DB.prepare("SELECT * FROM jobs WHERE id=?").bind(jobId).first();
  if (!row || row.state !== "queued" || row.expires_at < Date.now() / 1000) throw new ClientError("Job unavailable", 404);

  const metaObj = await s3(env).send(new GetObjectCommand({ Bucket: env.R2_BUCKET, Key: `jobs/${jobId}/metadata.enc` }));
  const meta = await decrypt(env, new Uint8Array(await metaObj.Body.transformToByteArray()));
  const runner = runnerIdentity(identity);
  const claimed = await env.DB.prepare("UPDATE jobs SET state='running', runner_claim=? WHERE id=? AND state='queued'")
    .bind(runner, jobId).run();
  if (!claimed.meta?.changes) throw new ClientError("Job unavailable", 404);

  const inputs = {};
  for (const slot of SLOTS) {
    const item = meta.uploads?.[slot];
    if (!item) throw new ClientError("Required input missing");
    inputs[slot] = await signedGet(env, item.key, `${slot}.bin`);
  }
  return json({
    job_id: jobId, inputs, password: meta.password, settings: meta.settings || {},
    result_put: await signedPut(env, `jobs/${jobId}/signed.ipa`), expires_at: row.expires_at
  }, 200, env);
}

export async function finishJob(request, env, identity) {
  const { job_id: jobId, state, error, app_info: appInfo } = await readJson(request);
  if (typeof jobId !== "string" || !["done", "failed"].includes(state)) throw new ClientError("Invalid completion");
  const row = await env.DB.prepare("SELECT state, runner_claim FROM jobs WHERE id=?").bind(jobId).first();
  if (!row || row.state !== "running" || row.runner_claim !== runnerIdentity(identity)) {
    throw new ClientError("Job unavailable", 404);
  }

  let finalState = state;
  let finalError = state === "failed" ? String(error || "Signing failed").slice(0, 500) : null;
  let info = state === "done" ? sanitizeAppInfo(appInfo) : null;
  if (state === "done") {
    try {
      const head = await s3(env).send(new HeadObjectCommand({ Bucket: env.R2_BUCKET, Key: `jobs/${jobId}/signed.ipa` }));
      if (!Number(head.ContentLength)) throw new Error("empty result");
    } catch (_) {
      finalState = "failed";
      finalError = "Signed IPA was not uploaded";
      info = null;
    }
  }
  const updated = await env.DB.prepare("UPDATE jobs SET state=?, error=?, app_info_json=?, runner_claim=NULL WHERE id=? AND state='running' AND runner_claim=?")
    .bind(finalState, finalError, info ? JSON.stringify(info) : null, jobId, runnerIdentity(identity)).run();
  if (!updated.meta?.changes) throw new ClientError("Job unavailable", 404);
  return json({ ok: true }, 200, env);
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(env) });
    const url = new URL(request.url), path = url.pathname;
    if (request.headers.get("Origin") && request.headers.get("Origin") !== env.ALLOWED_ORIGIN) {
      return fail("Origin not allowed", 403, env);
    }
    if (configProblem(env)) return fail("Service is not configured", 503, env);
    try {
      const match = path.match(/^\/v1\/jobs\/([A-Za-z0-9_-]+)(?:\/(complete|status))?$/);
      if (path === "/v1/jobs" && request.method === "POST") return await createJob(request, env);
      if (match && request.method === "POST" && match[2] === "complete") return await completeJob(request, env, match[1]);
      if (match && request.method === "GET" && match[2] === "status") return await jobStatus(request, env, match[1], url);
      if (path === "/internal/claim" && request.method === "POST") {
        return await claimJob(request, env, await verifyRunner(request, env));
      }
      if (path === "/internal/finish" && request.method === "POST") {
        return await finishJob(request, env, await verifyRunner(request, env));
      }
      const manifestMatch = path.match(/^\/v1\/jobs\/([A-Za-z0-9_-]+)\/manifest$/);
      if (manifestMatch && request.method === "GET") return await jobManifest(env, manifestMatch[1], url);
      return fail("Not found", 404, env);
    } catch (e) {
      if (e instanceof ClientError) return fail(e.message, e.status, env);
      console.error("SignHub broker error:", e);
      return fail("Request failed", 500, env);
    }
  },
  async scheduled(event, env) {
    const now = Math.floor(Date.now() / 1000);
    const expired = await env.DB.prepare("SELECT id FROM jobs WHERE expires_at < ?").bind(now).all();
    for (const row of expired.results || []) {
      const objects = await s3(env).send(new ListObjectsV2Command({ Bucket: env.R2_BUCKET, Prefix: `jobs/${row.id}/` }));
      for (const obj of objects.Contents || []) {
        await s3(env).send(new DeleteObjectCommand({ Bucket: env.R2_BUCKET, Key: obj.Key }));
      }
      await env.DB.prepare("DELETE FROM jobs WHERE id=?").bind(row.id).run();
    }
  }
};
