import { Router } from "itty-router";

type Video = {
  uid: string;
  thumbnail: string;
  thumbnailTimestampPct: number;
  readyToStream: boolean;
  status: {
    state: string;
    pctComplete: string;
    errorReasonCode: string;
    errorReasonText: string;
  };
  meta: {
    name: string;
  };
  created: string;
  modified: string;
  size: number;
  preview: string;
  allowedOrigins: string[];
  requireSignedURLs: boolean;
  uploaded: string;
  uploadExpiry: null;
  maxSizeBytes: null;
  maxDurationSeconds: null;
  duration: number;
  input: {
    width: number;
    height: number;
  };
  playback: {
    hls: string;
    dash: string;
  };
  watermark: null;
  liveInput: string;
};

type StreamListResponse = {
  success: boolean;
  errors: unknown[];
  messages: unknown[];
  result: Video[];
  total: string;
  range: string;
};

type FirstLoginResponse = {
  uid: string;
  email: string;
};

type Env = {
  STREAM_WEBHOOK_SECRET: string;
  STREAM_LIVE_WEBHOOK_SECRET: string;
  STREAM_ACCOUNT_ID: string;
  STREAM_API_TOKEN: string;
  AUTH0_WEBHOOK_SECRET: string;
  USER_DO: DurableObjectNamespace;
  SETTINGS_DO: DurableObjectNamespace;
  VIDEOS_KV: KVNamespace;
  CACHE_KV: KVNamespace;
  WEBHOOKS_KV: KVNamespace;
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

const withValidBody =
  <JSONBody>(
    secret: (request: Request, env: Env) => string,
    f: (request: Request, env: Env, body: JSONBody) => Promise<Response>
  ) =>
  async (request: Request, env: Env) => {
    const signatureHeader = request.headers.get("Webhook-Signature");
    if (signatureHeader === null) {
      return new Response("Missing Webhook-Signature header", { status: 422 });
    }

    if (!signatureHeader.match(/^time=\d+,sig1=\w+$/)) {
      return new Response("Invalid Webhook-Signature header", { status: 422 });
    }

    const processed = await env.WEBHOOKS_KV.get(signatureHeader);
    if (processed !== null) {
      return new Response("Conflict", { status: 409 });
    }

    const [time, signature] = signatureHeader
      .split(",")
      .map((s) => s.split("=")[1]);

    const body = await request.text();
    const message = `${time}.${body}`;
    const valid = await checkSignature(
      message,
      signature,
      secret(request, env)
    );

    if (!valid) {
      return new Response("Signature invalid", { status: 406 });
    }

    const json = JSON.parse(body);
    const response = await f(request, env, json);
    await env.WEBHOOKS_KV.put(signatureHeader, body);
    return response;
  };

const fetchVideos = async (
  env: Env,
  options: { limit?: number; status?: "ready"; search?: string } = {}
) => {
  const url = new URL(
    `https://api.cloudflare.com/client/v4/accounts/${env.STREAM_ACCOUNT_ID}/stream`
  );
  if (options.limit) url.searchParams.set("limit", options.limit.toString());
  if (options.status) url.searchParams.set("status", options.status);
  if (options.search) url.searchParams.set("search", options.search);

  const r = await fetch(url.toString(), {
    headers: new Headers({
      "Content-Type": "application/json",
      Authorization: `Bearer ${env.STREAM_API_TOKEN}`,
    }),
  });

  return r.json<StreamListResponse>();
};

const updateVideo = async (
  env: Env,
  id: string,
  options: { limit?: number; status?: "ready"; search?: string } = {}
) => {
  const url = new URL(
    `https://api.cloudflare.com/client/v4/accounts/${env.STREAM_ACCOUNT_ID}/stream`
  );
  if (options.limit) url.searchParams.set("limit", options.limit.toString());
  if (options.status) url.searchParams.set("status", options.status);
  if (options.search) url.searchParams.set("search", options.search);

  const r = await fetch(url.toString(), {
    headers: new Headers({
      "Content-Type": "application/json",
      Authorization: `Bearer ${env.STREAM_API_TOKEN}`,
    }),
  });

  return r.json<StreamListResponse>();
};

const router = Router();

const webhookCloudflareStream = withValidBody<Video>(
  (_request, env) => env.STREAM_WEBHOOK_SECRET,
  async (_request, env, video) => {
    const updateVideos = async () => {
      const stored = await env.VIDEOS_KV.get("latest");
      let latest: any[];

      if (stored) {
        latest = JSON.parse(stored);
        latest.unshift(video);
      } else {
        latest = (await fetchVideos(env, { limit: 10, status: "ready" }))
          .result;
      }

      await env.VIDEOS_KV.put("latest", JSON.stringify(latest));
    };

    const updateJKOT = async () => {
      if (!video.meta.name.includes("jkot-stream")) return;

      const latest = (
        await fetchVideos(env, { status: "ready", search: "jkot-stream" })
      ).result;

      await env.CACHE_KV.put("videos", JSON.stringify(latest));
    };

    await Promise.all([updateVideos(), updateJKOT()]);

    return new Response("ok", { status: 200 });
  }
);

const webhookAuth0StreamWorker = withValidBody<FirstLoginResponse>(
  (_request, env) => env.AUTH0_WEBHOOK_SECRET,
  async (request, env, user) => {
    const id = env.USER_DO.newUniqueId({ jurisdiction: "eu" });

    const stub = env.USER_DO.get(id);

    return await stub.fetch(`${new URL(request.url).origin}/new`, {
      method: "POST",
      body: JSON.stringify({ slug: id.toString(), ...user }),
    });
  }
);

router.post("/stream", webhookCloudflareStream);
router.post("/auth0/stream-worker", webhookAuth0StreamWorker);

export default {
  fetch: router.handle,
};
