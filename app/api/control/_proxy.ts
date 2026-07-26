const DEFAULT_CONTROL_API = "http://127.0.0.1:7071";
const MAX_JSON_BODY_BYTES = 64 * 1024;
const CONTROL_TIMEOUT_MS = 10_000;

const JSON_RESPONSE_HEADERS = {
  "cache-control": "no-store, max-age=0",
  "content-type": "application/json; charset=utf-8",
  "x-content-type-options": "nosniff",
} as const;

type ControlConfiguration =
  | { ok: true; base: URL; token: string }
  | { ok: false; error: string };

function jsonError(status: number, error: string) {
  return Response.json(
    { error },
    {
      status,
      headers: JSON_RESPONSE_HEADERS,
    },
  );
}

function controlConfiguration(): ControlConfiguration {
  const token = process.env.WEBCYBER_CONTROL_TOKEN?.trim();
  if (!token) {
    return {
      ok: false,
      error: "Kontrol hizmeti için sunucu kimlik bilgisi yapılandırılmamış.",
    };
  }

  const configuredBase =
    process.env.WEBCYBER_API_URL?.trim() || DEFAULT_CONTROL_API;

  try {
    const base = new URL(configuredBase);
    if (base.protocol !== "http:" && base.protocol !== "https:") {
      return { ok: false, error: "Kontrol hizmeti adresi geçersiz." };
    }
    base.username = "";
    base.password = "";
    base.hash = "";
    base.search = "";
    base.pathname = base.pathname.replace(/\/+$/, "");
    return { ok: true, base, token };
  } catch {
    return { ok: false, error: "Kontrol hizmeti adresi geçersiz." };
  }
}

async function boundedJSONBody(request: Request) {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) {
    return {
      error: jsonError(415, "İstek gövdesi application/json olmalı."),
    };
  }

  const declaredLength = Number(request.headers.get("content-length") ?? "0");
  if (
    Number.isFinite(declaredLength) &&
    declaredLength > MAX_JSON_BODY_BYTES
  ) {
    return { error: jsonError(413, "İstek gövdesi izin verilen sınırı aşıyor.") };
  }

  if (!request.body) return { body: new ArrayBuffer(0) };

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > MAX_JSON_BODY_BYTES) {
      await reader.cancel().catch(() => undefined);
      return {
        error: jsonError(413, "İstek gövdesi izin verilen sınırı aşıyor."),
      };
    }
    chunks.push(value);
  }

  const boundedBody = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    boundedBody.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { body: boundedBody.buffer };
}

function upstreamHeaders(response: Response, stream: boolean) {
  const headers = new Headers({
    "cache-control": stream
      ? "no-cache, no-store, max-age=0"
      : "no-store, max-age=0",
    "x-content-type-options": "nosniff",
  });
  const contentType = response.headers.get("content-type");

  if (contentType) {
    headers.set("content-type", contentType);
  } else {
    headers.set(
      "content-type",
      stream ? "text/event-stream; charset=utf-8" : "application/json; charset=utf-8",
    );
  }

  if (stream) {
    headers.set("x-accel-buffering", "no");
  }

  return headers;
}

export async function proxyControl(
  request: Request,
  path: string,
  options: { stream?: boolean } = {},
) {
  const configuration = controlConfiguration();
  if (!configuration.ok) {
    return jsonError(503, configuration.error);
  }

  const method = request.method.toUpperCase();
  let body: ArrayBuffer | undefined;
  if (method === "POST" || method === "PUT" || method === "PATCH") {
    const bounded = await boundedJSONBody(request);
    if ("error" in bounded) return bounded.error;
    body = bounded.body;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CONTROL_TIMEOUT_MS);
  const url = new URL(path, `${configuration.base.href}/`);

  try {
    const response = await fetch(url, {
      method,
      body,
      headers: {
        accept: options.stream ? "text/event-stream" : "application/json",
        authorization: `Bearer ${configuration.token}`,
        ...(body ? { "content-type": "application/json" } : {}),
      },
      cache: "no-store",
      redirect: "manual",
      signal: controller.signal,
    });

    clearTimeout(timeout);
    return new Response(response.body, {
      status: response.status,
      headers: upstreamHeaders(response, Boolean(options.stream)),
    });
  } catch (error) {
    clearTimeout(timeout);
    const timedOut = error instanceof DOMException && error.name === "AbortError";
    return jsonError(
      timedOut ? 504 : 503,
      timedOut
        ? "Kontrol hizmeti zamanında yanıt vermedi."
        : "Kontrol hizmetine ulaşılamıyor.",
    );
  }
}

export function validScanID(id: string) {
  return /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(id);
}

export function invalidScanID() {
  return jsonError(400, "Tarama kimliği geçersiz.");
}
