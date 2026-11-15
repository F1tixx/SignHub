import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { SignJWT, importPKCS8, createRemoteJWKSet, jwtVerify } from "jose";

const cors = (env) => ({
  "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
  "Access-Control-Max-Age": "86400",
  "Vary": "Origin"
});
const json = (data, status, env) => new Response(JSON.stringify(data), {
  status: status || 200, headers: { ...cors(env), "Content-Type": "application/json", "Cache-Control": "no-store" }
});
const fail = (message, status, env) => json({ error: message }, status, env);
const s3 = env => new S3Client({
  region: "auto",
  endpoint: `https://${env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: env.R2_ACCESS_KEY_ID, secretAccessKey: env.R2_SECRET_ACCESS_KEY }
});
const hex = bytes => [...new Uint8Array(bytes)].map(x => x.toString(16).padStart(2, "0")).join("");
const sha = async value => hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
const random = (n=32) => { const b = crypto.getRandomValues(new Uint8Array(n)); return btoa(String.fromCharCode(...b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); };
const key = async env => crypto.subtle.importKey("raw", Uint8Array.from(atob(env.JOB_ENCRYPTION_KEY), c => c.charCodeAt(0)), "AES-GCM", false, ["encrypt","decrypt"]);
async function encrypt(env, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await key(env), new TextEncoder().encode(JSON.stringify(value)));
  return new Uint8Array([...iv, ...new Uint8Array(data)]);
}
async function decrypt(env, value) {
  const bytes = new Uint8Array(value), iv = bytes.slice(0,12), data = bytes.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, await key(env), data);
  return JSON.parse(new TextDecoder().decode(plain));
}
async function signedPut(env, objectKey, contentType="application/octet-stream") {
  return getSignedUrl(s3(env), new PutObjectCommand({ Bucket: env.R2_BUCKET, Key: objectKey, ContentType: contentType }), { expiresIn: 900 });
}
async function signedGet(env, objectKey, filename) {
  return getSignedUrl(s3(env), new GetObjectCommand({ Bucket: env.R2_BUCKET, Key: objectKey, ResponseContentDisposition: `attachment; filename="${filename || "signed.ipa"}"` }), { expiresIn: 3600 });
}
async function appToken(env) {
  const pk = await importPKCS8(env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g,"\n"), "RS256");
  const now = Math.floor(Date.now()/1000);
  const assertion = await new SignJWT({ iat: now-30, exp: now+540, iss: env.GITHUB_APP_ID })
    .setProtectedHeader({ alg:"RS256" }).sign(pk);
  const r = await fetch(`https://api.github.com/app/installations/${env.GITHUB_APP_INSTALLATION_ID}/access_tokens`, {
    method:"POST", headers:{ Authorization:`Bearer ${assertion}`, Accept:"application/vnd.github+json", "X-GitHub-Api-Version":"2022-11-28", "Content-Type":"application/json" }, body:"{}"
  });
  if (!r.ok) throw new Error("Could not authorize GitHub App");
  return (await r.json()).token;
}
async function dispatch(env, jobId) {
  const token = await appToken(env);
  const r = await fetch(`https://api.github.com/repos/${env.GITHUB_REPOSITORY}/actions/workflows/signhub-sign.yml/dispatches`, {
    method:"POST", headers:{ Authorization:`Bearer ${token}`, Accept:"application/vnd.github+json", "X-GitHub-Api-Version":"2022-11-28", "Content-Type":"application/json" },
    body:JSON.stringify({ ref: env.GITHUB_REF || "main", inputs:{ job_id:jobId } })
  });
  if (!r.ok) throw new Error("GitHub workflow dispatch failed");
}
async function verifyRunner(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i,"");
  if (!token) throw new Error("Missing runner identity");
  const jwks = createRemoteJWKSet(new URL("https://token.actions.githubusercontent.com/.well-known/jwks"));
  const { payload } = await jwtVerify(token, jwks, { issuer:"https://token.actions.githubusercontent.com", audience:"signhub-worker" });
  if (payload.repository !== env.GITHUB_REPOSITORY || payload.ref !== (env.GITHUB_REF || "refs/heads/main") ||
      !String(payload.workflow_ref || "").endsWith("/.github/workflows/signhub-sign.yml@"+(env.GITHUB_REF || "refs/heads/main"))) {
    throw new Error("Runner identity is not authorized");
  }
  return payload;
}
export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null,{headers:cors(env)});
    const url = new URL(request.url), path = url.pathname;
    if (request.headers.get("Origin") && request.headers.get("Origin") !== env.ALLOWED_ORIGIN) return fail("Origin not allowed",403,env);
    try {
      if (path === "/v1/jobs" && request.method === "POST") {
        const body = await request.json();
        if (!Array.isArray(body.files) || body.files.length < 3 || body.files.length > 12) return fail("Invalid file list",400,env);
        const allowed = new Set(["ipa","p12","profile", ...Array.from({length:8},(_,i)=>`tweak_${i}`)]);
        const id = random(18), owner = random(32), expires = Math.floor(Date.now()/1000)+86400;
        const uploads = {};
        for (const f of body.files) {
          if (!allowed.has(f.slot) || !Number.isSafeInteger(f.size) || f.size < 1 || f.size > 5*1024*1024*1024) return fail("Invalid upload slot or size",400,env);
          const objectKey = `jobs/${id}/input/${f.slot}`;
          uploads[f.slot] = { key:objectKey, url:await signedPut(env,objectKey,f.type || "application/octet-stream") };
        }
        await env.DB.prepare("INSERT INTO jobs (id, owner_hash, state, created_at, expires_at, uploads_json) VALUES (?, ?, 'uploading', ?, ?, ?)")
          .bind(id, await sha(owner+env.OWNER_TOKEN_PEPPER), Math.floor(Date.now()/1000), expires, JSON.stringify(uploads)).run();
        return json({ job_id:id, owner_token:owner, expires_at:expires, uploads },201,env);
      }
      const match = path.match(/^\/v1\/jobs\/([A-Za-z0-9_-]+)(?:\/(complete|status))?$/);
      if (match && request.method === "POST" && match[2] === "complete") {
        const id = match[1], body = await request.json(), owner = (request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
        const row = await env.DB.prepare("SELECT * FROM jobs WHERE id=?").bind(id).first();
        if (!row || row.expires_at < Date.now()/1000 || !owner || await sha(owner+env.OWNER_TOKEN_PEPPER) !== row.owner_hash) return fail("Job not found",404,env);
        if (row.state !== "uploading") return fail("Job already submitted",409,env);
        const uploads = JSON.parse(row.uploads_json);
        for (const slot of ["ipa","p12","profile"]) {
          if (!uploads[slot]) return fail("Required input missing",400,env);
          await s3(env).send(new HeadObjectCommand({Bucket:env.R2_BUCKET,Key:uploads[slot].key}));
        }
        if (typeof body.p12_password !== "string" || !body.p12_password || body.p12_password.length > 1024) return fail("P12 password required",400,env);
        const metadata = { password:body.p12_password, settings:body.settings || {}, uploads };
        await s3(env).send(new PutObjectCommand({Bucket:env.R2_BUCKET,Key:`jobs/${id}/metadata.enc`,Body:await encrypt(env,metadata),ContentType:"application/octet-stream"}));
        await env.DB.prepare("UPDATE jobs SET state='queued' WHERE id=?").bind(id).run();
        await dispatch(env,id);
        return json({ job_id:id, state:"queued", expires_at:row.expires_at },202,env);
      }
      if (match && request.method === "GET" && match[2] === "status") {
        const id=match[1], owner=(request.headers.get("Authorization")||"").replace(/^Bearer\s+/i,"");
        const row=await env.DB.prepare("SELECT * FROM jobs WHERE id=?").bind(id).first();
        if(!row || row.expires_at < Date.now()/1000 || !owner || await sha(owner+env.OWNER_TOKEN_PEPPER)!==row.owner_hash) return fail("Job not found",404,env);
        const result={job_id:id,state:row.state,error:row.error || null,expires_at:row.expires_at};
        if(row.state==="done") {
          result.download_url=await signedGet(env,`jobs/${id}/signed.ipa`,"signed.ipa");
          result.manifest_url=await signedGet(env,`jobs/${id}/manifest.plist`,"manifest.plist");
          result.install_url=`itms-services://?action=download-manifest&url=${encodeURIComponent(result.manifest_url)}`;
        }
        return json(result,200,env);
      }
      if (path === "/internal/claim" && request.method === "POST") {
        await verifyRunner(request,env);
        const {job_id}=await request.json();
        const row=await env.DB.prepare("SELECT * FROM jobs WHERE id=?").bind(job_id).first();
        if(!row || row.state!=="queued" || row.expires_at < Date.now()/1000) return fail("Job unavailable",404,env);
        const metaObj=await s3(env).send(new GetObjectCommand({Bucket:env.R2_BUCKET,Key:`jobs/${job_id}/metadata.enc`}));
        const meta=await decrypt(env, new Uint8Array(await metaObj.Body.transformToByteArray()));
        const inputs={};
        for(const [slot,item] of Object.entries(meta.uploads)) inputs[slot]=await signedGet(env,item.key,`${slot}.bin`);
        const resultKey=`jobs/${job_id}/signed.ipa`;
        const manifestKey=`jobs/${job_id}/manifest.plist`;
        const resultPut=await signedPut(env,resultKey,"application/octet-stream");
        const manifestPut=await signedPut(env,manifestKey,"application/xml");
        await env.DB.prepare("UPDATE jobs SET state='running' WHERE id=?").bind(job_id).run();
        return json({job_id,inputs,password:meta.password,settings:meta.settings,result_put:resultPut,manifest_put:manifestPut,expires_at:row.expires_at},200,env);
      }
      if (path === "/internal/finish" && request.method === "POST") {
        await verifyRunner(request,env);
        const {job_id,state,error}=await request.json();
        if(!job_id || !["done","failed"].includes(state)) return fail("Invalid completion",400,env);
        await env.DB.prepare("UPDATE jobs SET state=?, error=? WHERE id=? AND state='running'").bind(state,error ? String(error).slice(0,500) : null,job_id).run();
        return json({ok:true},200,env);
      }
      return fail("Not found",404,env);
    } catch (e) {
      return fail(e && e.message ? e.message : "Request failed",500,env);
    }
  },
  async scheduled(event,env,ctx) {
    const now=Math.floor(Date.now()/1000);
    const expired=await env.DB.prepare("SELECT id FROM jobs WHERE expires_at < ?").bind(now).all();
    for(const row of expired.results || []) {
      const objects=await s3(env).send(new (await import("@aws-sdk/client-s3")).ListObjectsV2Command({Bucket:env.R2_BUCKET,Prefix:`jobs/${row.id}/`}));
      for(const obj of objects.Contents || []) await s3(env).send(new (await import("@aws-sdk/client-s3")).DeleteObjectCommand({Bucket:env.R2_BUCKET,Key:obj.Key}));
      await env.DB.prepare("DELETE FROM jobs WHERE id=?").bind(row.id).run();
    }
  }
};