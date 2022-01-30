
import { Router } from 'itty-router'

type Env = {
  STREAM_WEBHOOK_SECRET: string,
  VIDEOS_KV: KVNamespace
}

const router = Router()

const webhookStream = async (request: Request, env: Env) => {
  const signatureHeader = request.headers.get("Webhook-Signature");
  if (signatureHeader === null) {
    return new Response("Missing Webhook-Signature header", { status: 400 });
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

  const value = await env.VIDEOS_KV.get("latest");

  const latest: any[] = value ? JSON.parse(value) : [];
  latest.unshift(video);

  await env.VIDEOS_KV.put("latest", JSON.stringify(latest));

  return new Response("", { status: 200 });
}

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

router.post("/stream", webhookStream)

export default {
  fetch: router.handle,
};