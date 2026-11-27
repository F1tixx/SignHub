import { after, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { S3Client } from "@aws-sdk/client-s3";
import worker, {
  LIMITS, validateFiles, sanitizeSettings, sanitizeAppInfo, xmlEscape, runnerIdentity, claimJob, finishJob
} from "../src/index.js";

const ORIGIN = "https://signhub.test";
const IDENTITY = { repository: "F1tixx/SignHub", run_id: "42", run_attempt: "1" };
const APP_PRIVATE_KEY = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" }
}).privateKey;
const files = [
  { slot: "ipa", size: 100 },
  { slot: "p12", size: 50 },
  { slot: "profile", size: 20 }
];

let env, objects, dbRows, realSend;

function makeEnv() {
  return {
    R2_ACCOUNT_ID: "testaccount",
    R2_ACCESS_KEY_ID: "testkey",
    R2_SECRET_ACCESS_KEY: "testsecret",
    R2_BUCKET: "test-bucket",
    GITHUB_APP_ID: "123",
    GITHUB_APP_INSTALLATION_ID: "456",
    GITHUB_APP_PRIVATE_KEY: APP_PRIVATE_KEY,
    GITHUB_REPOSITORY: "F1tixx/SignHub",
    GITHUB_REF: "refs/heads/main",
    ALLOWED_ORIGIN: ORIGIN,
    JOB_ENCRYPTION_KEY: Buffer.from("0123456789abcdef0123456789abcdef").toString("base64"),
    OWNER_TOKEN_PEPPER: "a-long-random-pepper"
  };
}

function makeDb() {
  return {
    rows: dbRows,
    prepare(sql) {
      const bound = (...args) => ({
        first: async () => first(sql, args),
        all: async () => ({ results: all(sql, args) }),
        run: async () => run(sql, args)
      });
      return { bind: bound, first: async () => first(sql, []), all: async () => ({ results: all(sql, []) }), run: async () => run(sql, []) };
    }
  };
}

function first(sql, args) {
  if (sql.includes("SELECT COUNT(*)")) return { n: [...dbRows.values()].filter(r => r.client_hash === args[0] && r.created_at > args[1]).length };
  if (sql.includes("SELECT state, runner_claim")) {
    const r = dbRows.get(args[0]);
    return r ? { state: r.state, runner_claim: r.runner_claim } : null;
  }
  if (sql.includes("SELECT * FROM jobs")) return dbRows.get(args[0]) || null;
  return null;
}

function all(sql, args) {
  if (sql.includes("SELECT id FROM jobs WHERE expires_at")) {
    return [...dbRows.values()].filter(r => r.expires_at < args[0]).map(r => ({ id: r.id }));
  }
  return [];
}

function run(sql, args) {
  const changed = n => ({ meta: { changes: n } });
  if (sql.startsWith("INSERT INTO jobs")) {
    const [id, ownerHash, clientHash, createdAt, expiresAt, uploadsJson] = args;
    dbRows.set(id, {
      id, owner_hash: ownerHash, client_hash: clientHash, state: "uploading",
      created_at: createdAt, expires_at: expiresAt, uploads_json: uploadsJson,
      error: null, app_info_json: null, runner_claim: null
    });
    return changed(1);
  }
  const r = dbRows.get(args[args.length - 1]);
  if (sql.includes("state='queued' WHERE id=? AND state='uploading'")) {
    if (!r || r.state !== "uploading") return changed(0);
    r.state = "queued";
    return changed(1);
  }
  if (sql.includes("state='failed', error=?")) {
    if (!r) return changed(0);
    r.state = "failed"; r.error = args[0];
    return changed(1);
  }
  if (sql.includes("state='running', runner_claim=?")) {
    if (!r || r.state !== "queued") return changed(0);
    r.state = "running"; r.runner_claim = args[0];
    return changed(1);
  }
  if (sql.includes("app_info_json=?, runner_claim=NULL")) {
    const [state, error, info, id, runner] = args;
    const target = dbRows.get(id);
    if (!target || target.state !== "running" || target.runner_claim !== runner) return changed(0);
    target.state = state; target.error = error; target.app_info_json = info; target.runner_claim = null;
    return changed(1);
  }
  if (sql.startsWith("DELETE FROM jobs")) return changed(dbRows.delete(args[0]) ? 1 : 0);
  return changed(0);
}

function seed(key, size) {
  objects.set(key, { bytes: new Uint8Array(size), size });
}

function request(path, { method = "GET", body, headers = {} } = {}) {
  return new Request(`${ORIGIN}${path}`, {
    method,
    headers: { Origin: ORIGIN, ...headers },
    body: body === undefined ? undefined : JSON.stringify(body)
  });
}

async function createJob() {
  const res = await worker.fetch(request("/v1/jobs", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "1.2.3.4" },
    body: { files }
  }), env);
  assert.equal(res.status, 201);
  const data = await res.json();
  for (const slot of ["ipa", "p12", "profile"]) seed(data.uploads[slot].key, data.uploads[slot].size);
  return data;
}

async function completeJob(data, password = "correct horse", settings = { bundle_id: "com.test.app" }) {
  return worker.fetch(request(`/v1/jobs/${data.job_id}/complete`, {
    method: "POST",
    headers: { Authorization: `Bearer ${data.owner_token}`, "Content-Type": "application/json" },
    body: { p12_password: password, settings }
  }), env);
}

beforeEach(() => {
  env = makeEnv();
  env.DB = makeDb();
  objects = new Map();
  dbRows = new Map();
  realSend = S3Client.prototype.send;
  S3Client.prototype.send = async function (command) {
    const input = command.input;
    const name = command.constructor.name;
    if (name === "PutObjectCommand") {
      const size = input.Body instanceof Uint8Array ? input.Body.length : Buffer.byteLength(String(input.Body ?? ""));
      objects.set(input.Key, { bytes: input.Body, size });
      return {};
    }
    if (name === "HeadObjectCommand") {
      const object = objects.get(input.Key);
      if (!object) throw new Error("NotFound");
      return { ContentLength: object.size };
    }
    if (name === "GetObjectCommand") {
      const object = objects.get(input.Key);
      if (!object) throw new Error("NotFound");
      return { Body: { transformToByteArray: async () => object.bytes } };
    }
    if (name === "ListObjectsV2Command") {
      return { Contents: [...objects.keys()].filter(k => k.startsWith(input.Prefix)).map(Key => ({ Key })) };
    }
    if (name === "DeleteObjectCommand") {
      objects.delete(input.Key);
      return {};
    }
    throw new Error(`Unexpected S3 command ${name}`);
  };
  globalThis.fetch = async url => String(url).includes("/access_tokens")
    ? new Response(JSON.stringify({ token: "app-token" }), { status: 200 })
    : new Response(null, { status: 204 });
});

after(() => {
  S3Client.prototype.send = realSend;
});

test("validateFiles requires exactly the three known slots and safe sizes", () => {
  assert.equal(validateFiles(files), files);
  assert.equal(validateFiles([...files, { slot: "tweak_0", size: 1 }]), null);
  assert.equal(validateFiles([files[0], files[0], files[2]]), null);
  assert.equal(validateFiles(files.map(f => f.slot === "ipa" ? { slot: "ipa", size: LIMITS.ipa + 1 } : f)), null);
  assert.equal(validateFiles(files.map(f => f.slot === "ipa" ? { slot: "ipa", size: 1.5 } : f)), null);
  assert.equal(validateFiles([files[0], files[1], { slot: "toString", size: 1 }]), null);
});

test("settings, app info, XML and runner identity are sanitized", () => {
  assert.deepEqual(sanitizeSettings({ bundle_id: " com.test.app ", bundle_name: "A\u0000B", other: "x" }), { bundle_id: "com.test.app" });
  assert.deepEqual(sanitizeAppInfo({ bundle_id: "com.test.app", bad: 7 }), { bundle_id: "com.test.app" });
  assert.equal(xmlEscape('A & B <C> "D"'), "A &amp; B &lt;C&gt; &quot;D&quot;");
  assert.equal(runnerIdentity(IDENTITY), "F1tixx/SignHub:42:1");
});

test("origin mismatch and unconfigured workers are rejected generically", async () => {
  const badOrigin = await worker.fetch(request("/v1/jobs", {
    method: "POST", headers: { Origin: "https://evil.test" }, body: { files }
  }), env);
  assert.equal(badOrigin.status, 403);

  const unconfigured = { ...env, ALLOWED_ORIGIN: "https://YOUR-SECURE-SITE.example" };
  const unconfiguredRequest = new Request(`${ORIGIN}/v1/jobs`, {
    method: "POST",
    headers: { Origin: unconfigured.ALLOWED_ORIGIN, "Content-Type": "application/json" },
    body: JSON.stringify({ files })
  });
  const res = await worker.fetch(unconfiguredRequest, unconfigured);
  assert.equal(res.status, 503);
  assert.deepEqual(await res.json(), { error: "Service is not configured" });
});

test("a job owner can check status but a different token cannot", async () => {
  const data = await createJob();
  const denied = await worker.fetch(request(`/v1/jobs/${data.job_id}/status`, {
    headers: { Authorization: "Bearer wrong" }
  }), env);
  assert.equal(denied.status, 404);

  const ok = await worker.fetch(request(`/v1/jobs/${data.job_id}/status`, {
    headers: { Authorization: `Bearer ${data.owner_token}` }
  }), env);
  assert.equal(ok.status, 200);
  assert.equal((await ok.json()).state, "uploading");
});

test("completion rejects a size mismatch and accepts a verified upload", async () => {
  const data = await createJob();
  const key = data.uploads.ipa.key;
  seed(key, 10);
  const mismatch = await completeJob(data);
  assert.equal(mismatch.status, 400);
  assert.match((await mismatch.json()).error, /size does not match/i);
  seed(key, data.uploads.ipa.size);

  const ok = await completeJob(data);
  assert.equal(ok.status, 202);
  assert.equal((await ok.json()).state, "queued");
});

test("only three jobs per client hash are allowed in an hour", async () => {
  await createJob();
  await createJob();
  await createJob();
  const limited = await worker.fetch(request("/v1/jobs", {
    method: "POST", headers: { "CF-Connecting-IP": "1.2.3.4" }, body: { files }
  }), env);
  assert.equal(limited.status, 429);
});

test("claim binds the job to one run and finish requires that run", async () => {
  const data = await createJob();
  assert.equal((await completeJob(data)).status, 202);

  const claimReq = request("/internal/claim", { method: "POST", body: { job_id: data.job_id } });
  const claim = await claimJob(claimReq, env, IDENTITY);
  assert.equal(claim.status, 200);
  const details = await claim.json();
  assert.equal(details.password, "correct horse");
  assert.equal(details.settings.bundle_id, "com.test.app");

  await assert.rejects(
    () => finishJob(request("/internal/finish", {
      method: "POST", body: { job_id: data.job_id, state: "done", app_info: {} }
    }), env, { ...IDENTITY, run_id: "99" }),
    /Job unavailable/
  );

  const noResult = await finishJob(request("/internal/finish", {
    method: "POST", body: { job_id: data.job_id, state: "done", app_info: {} }
  }), env, IDENTITY);
  assert.equal(noResult.status, 200);
  assert.equal(dbRows.get(data.job_id).state, "failed");

  dbRows.get(data.job_id).state = "running";
  dbRows.get(data.job_id).runner_claim = runnerIdentity(IDENTITY);
  seed(`jobs/${data.job_id}/signed.ipa`, 256);
  const done = await finishJob(request("/internal/finish", {
    method: "POST",
    body: { job_id: data.job_id, state: "done", app_info: { bundle_name: "A & B <C>" } }
  }), env, IDENTITY);
  assert.equal(done.status, 200);
  assert.equal(dbRows.get(data.job_id).state, "done");
});

test("manifest requires the owner token and escapes app metadata", async () => {
  const data = await createJob();
  const row = dbRows.get(data.job_id);
  row.state = "done";
  row.app_info_json = JSON.stringify({ bundle_id: "com.test.app", bundle_version: "1.0", bundle_name: "A & B <C>" });
  seed(`jobs/${data.job_id}/signed.ipa`, 256);

  const denied = await worker.fetch(request(`/v1/jobs/${data.job_id}/manifest?token=wrong`), env);
  assert.equal(denied.status, 404);

  const ok = await worker.fetch(request(`/v1/jobs/${data.job_id}/manifest?token=${encodeURIComponent(data.owner_token)}`), env);
  assert.equal(ok.status, 200);
  const text = await ok.text();
  assert.match(text, /com\.test\.app/);
  assert.match(text, /A &amp; B &lt;C&gt;/);
  assert.match(text, /<key>kind<\/key><string>software-package<\/string>/);
});
