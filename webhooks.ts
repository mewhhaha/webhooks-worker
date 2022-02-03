import { Router } from "itty-router";

type StreamVideoResponse = {
  success: boolean;
  errors: unknown[];
  messages: unknown[];
  result: any[];
  total: string;
  range: string;
};

type FirstLoginResponse = {
  uid: string;
  email: string;
};

type Env = {
  STREAM_WEBHOOK_SECRET: string;
  STREAM_ACCOUNT_ID: string;
  STREAM_API_TOKEN: string;
  AUTH0_WEBHOOK_SECRET: string;
  VIDEOS_KV: KVNamespace;
  USER_DO: DurableObjectNamespace;
};

const checkSignature = async (
  message: string,
  signature: string,
  secret: string
) => {
  const getUtf8Bytes = (str: string) =>
    new Uint8Array(
      [...decodeURIComponent(encodeURIComponent(str))].map((c) =>
        c.charCodeAt(0)
      )
    );

  const keyBytes = getUtf8Bytes(secret);
  const messageBytes = getUtf8Bytes(message);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    true,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, messageBytes);

  return (
    signature ===
    [...new Uint8Array(sig)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
};

const fetchVideos = async (env: Env) => {
  const url = new URL(
    `https://api.cloudflare.com/client/v4/accounts/${env.STREAM_ACCOUNT_ID}/stream`
  );
  url.searchParams.set("limit", "10");
  url.searchParams.set("status", "ready");

  const r = await fetch(url.toString(), {
    headers: new Headers({
      "Content-Type": "application/json",
      Authorization: `Bearer ${env.STREAM_API_TOKEN}`,
    }),
  });

  return r.json<StreamVideoResponse>();
};

const router = Router();

const webhookStream = async (request: Request, env: Env) => {
  const signatureHeader = request.headers.get("Webhook-Signature");
  if (signatureHeader === null) {
    return new Response("Missing Webhook-Signature header", { status: 422 });
  }

  const [time, signature] = signatureHeader
    .split(",")
    .map((s) => s.split("=")[1]);

  const body = await request.text();
  const message = `${time}.${body}`;
  const valid = await checkSignature(
    message,
    signature,
    env.STREAM_WEBHOOK_SECRET
  );
  if (!valid) {
    return new Response("Signature invalid", { status: 406 });
  }

  const video = JSON.parse(body);

  const stored = await env.VIDEOS_KV.get("latest");
  let latest: any[];

  if (stored) {
    latest = JSON.parse(stored);
    latest.unshift(video);
  } else {
    latest = (await fetchVideos(env)).result;
  }

  await env.VIDEOS_KV.put("latest", JSON.stringify(latest));

  return new Response("ok", { status: 200 });
};

const webhookStreamWorkerFirstLogin = async (request: Request, env: Env) => {
  const signatureHeader = request.headers.get("Webhook-Signature");
  if (signatureHeader === null) {
    return new Response("Missing Webhook-Signature header", { status: 422 });
  }

  const [time, signature] = signatureHeader
    .split(",")
    .map((s) => s.split("=")[1]);

  const body = await request.text();
  const message = `${time}.${body}`;
  const valid = await checkSignature(
    message,
    signature,
    env.AUTH0_WEBHOOK_SECRET
  );
  if (!valid) {
    return new Response("Signature invalid", { status: 406 });
  }

  const user = JSON.parse(body) as FirstLoginResponse;

  const id = env.USER_DO.newUniqueId({ jurisdiction: "eu" });

  const stub = env.USER_DO.get(id);

  await stub.fetch(`${new URL(request.url).origin}/new`, {
    method: "POST",
    body: JSON.stringify({ slug: id.toString(), ...user }),
  });

  return new Response("ok", { status: 200 });
};

router.post("/stream", webhookStream);
router.post("/auth0/stream-worker", webhookStreamWorkerFirstLogin);

export default {
  fetch(request: Request, env: Env) {
    return router.handle(request, env);
  },
};
