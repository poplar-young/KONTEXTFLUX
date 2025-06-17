// @deno-types="npm:@types/ws"

import {
  Application,
  Router,
  Status,
} from "https://deno.land/x/oak@v12.6.1/mod.ts";
import md5 from "https://esm.sh/md5@2.3.0";
import { encodeBase64 as encode, decodeBase64 as decode } from "https://deno.land/std@0.217.0/encoding/base64.ts";
import WebSocket from "npm:ws";

// --- 環境變數讀取 ---
const ENV_KONTEXTFLUX_TOKEN = Deno.env.get("KONTEXTFLUX_TOKEN");
// 修改这里：移除Deno.exit调用，改为设置变量标记缺少token
let isMissingToken = false;
if (!ENV_KONTEXTFLUX_TOKEN) {
  console.error("Error: KONTEXTFLUX_TOKEN environment variable is not set.");
  isMissingToken = true;
}

// --- 類型定義 ---
interface ChatMessage {
  role: string;
  content: string | Array<{ type: string; text?: string; image_url?: { url: string } }>;
  reasoning_content?: string;
}
interface ChatRequest {
  model: string;
  messages: ChatMessage[];
  stream?: boolean;
  size?: string;
}
interface StreamChoice {
  delta: { role?: string; content?: string; reasoning_content?: string };
  index: number;
  finish_reason: string | null;
}
interface StreamResponse {
  id: string;
  object: "chat.completion.chunk";
  created: number;
  model: string;
  choices: StreamChoice[];
}

// --- KontextFluxEncryptor 加密邏輯 ---
class KontextFluxEncryptor {
  private kis: string;
  private ra1: string;
  private ra2: string;
  private random: number;
  private textEncoder = new TextEncoder();
  private textDecoder = new TextDecoder();

  constructor(configData: any) {
    this.kis = configData.kis;
    this.ra1 = configData.ra1;
    this.ra2 = configData.ra2;
    this.random = configData.random;
  }

  private async aesDecrypt(keyStr: string, ivStr: string, ciphertextB64: string): Promise<string> {
    const key = await crypto.subtle.importKey(
      "raw",
      this.textEncoder.encode(keyStr),
      { name: "AES-CBC", length: 256 },
      false,
      ["decrypt"]
    );
    const iv = this.textEncoder.encode(ivStr);
    const ciphertext = decode(ciphertextB64);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv },
      key,
      ciphertext
    );
    return this.textDecoder.decode(decrypted);
  }

  private async aesEncrypt(keyStr: string, ivStr: string, plaintext: string): Promise<string> {
    const key = await crypto.subtle.importKey(
      "raw",
      this.textEncoder.encode(keyStr),
      { name: "AES-CBC", length: 256 },
      false,
      ["encrypt"]
    );
    const iv = this.textEncoder.encode(ivStr);
    const encodedPlaintext = this.textEncoder.encode(plaintext);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      key,
      encodedPlaintext
    );
    return encode(encrypted);
  }

  async getXtxHash(payload: Record<string, any>): Promise<string> {
    const sortedKeys = Object.keys(payload).sort();
    const serializedParts = sortedKeys.map(key => {
      const value = payload[key];
      const stringifiedValue = JSON.stringify(value);
      const safeValue = stringifiedValue.replace(/<|>/g, "");
      const encodedValue = encode(this.textEncoder.encode(safeValue));
      return `${key}=${encodedValue}`;
    });
    const serializedPayload = serializedParts.join("");
    const decodedKisStr = this.textDecoder.decode(decode(this.kis));
    const decodedKis = decodedKisStr.split("=sj+Ow2R/v");
    const randomStr = String(this.random);
    const y = parseInt(randomStr[0], 10);
    const b = parseInt(randomStr.slice(-1), 10);
    const k = parseInt(randomStr.substring(2, 2 + y), 10);
    const s_idx = parseInt(randomStr.substring(4 + y, 4 + y + b), 10);
    const intermediateKey = decodedKis[k];
    const intermediateIv = decodedKis[s_idx];
    const mainKey = await this.aesDecrypt(intermediateKey, intermediateIv, this.ra1);
    const mainIv = await this.aesDecrypt(intermediateKey, intermediateIv, this.ra2);
    const encryptedPayload = await this.aesEncrypt(mainKey, mainIv, serializedPayload);
    const finalHash = md5(encryptedPayload);
    return finalHash;
  }
}

// --- 公共 Header ---
const COMMON_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0",
  "Origin": "https://kontextflux.com",
  "Referer": "https://kontextflux.com/",
};

// --- API 交互函數 ---
async function getKontextFluxConfig(token: string) {
  const url = "https://api.kontextflux.com/client/common/getConfig";
  const payload = { token, referrer: "" };
  const response = await fetch(url, {
    method: "POST",
    headers: { ...COMMON_HEADERS, "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Failed to get config, status: ${response.status}`);
  }
  const data = await response.json();
  if (!data.data) {
    throw new Error("Invalid token or failed to retrieve config data.");
  }
  return data.data;
}

async function uploadFile(config: any, imageBytes: Uint8Array, filename: string = "image.png") {
  const url = "https://api.kontextflux.com/client/resource/uploadFile";
  const encryptor = new KontextFluxEncryptor(config);
  const xtx = await encryptor.getXtxHash({});
  const formData = new FormData();
  formData.append("file", new Blob([imageBytes], { type: "image/png" }), filename);
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...COMMON_HEADERS,
      "Authorization": config.token,
      "xtx": xtx,
    },
    body: formData,
  });
  if (!response.ok) {
    throw new Error(`File upload failed, status: ${response.status}`);
  }
  const data = await response.json();
  if (!data.data) {
    throw new Error(`Upload file returned invalid data: ${JSON.stringify(data)}`);
  }
  return data.data;
}

async function createDrawTask(config: any, prompt: string, keys: string[] = [], size = "auto") {
  const url = "https://api.kontextflux.com/client/styleAI/draw";
  const payload = { keys, prompt, size };
  const encryptor = new KontextFluxEncryptor(config);
  const xtx = await encryptor.getXtxHash(payload);
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      ...COMMON_HEADERS,
      "Content-Type": "application/json",
      "Authorization": config.token,
      "xtx": xtx,
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Create draw task failed, status: ${response.status}`);
  }
  const data = await response.json();
  if (!data || !data.data || !data.data.id) {
    throw new Error(`Create draw task returned invalid data: ${JSON.stringify(data)}`);
  }
  return data.data.id;
}

async function processImageUrl(imageUrl: string): Promise<Uint8Array | null> {
  try {
    if (imageUrl.startsWith('data:image/')) {
      const b64 = imageUrl.split(',')[1];
      return decode(b64);
    } else if (imageUrl.startsWith('http')) {
      const response = await fetch(imageUrl, {
        headers: { "User-Agent": COMMON_HEADERS["User-Agent"] }
      });
      if (!response.ok) return null;
      const buffer = await response.arrayBuffer();
      return new Uint8Array(buffer);
    }
    return null;
  } catch (error) {
    console.error(`Error processing image URL: ${error.message}`);
    return null;
  }
}

// --- 參數解析（完全對齊 main.py） ---
const VALID_SIZES = ["auto", "2:3", "3:2", "1:1"];

function parsePromptParameters(prompt: string): { cleanedPrompt: string; size: string } {
  // 支援 --size 2:3、--size=2:3、size:2:3、size 2:3、size=2:3 及純 3:2、2:3、1:1
  let size = "auto";
  let cleanedPrompt = prompt;

  // 先找明確參數
  const sizePatterns = [
    /--size[=\s]+([^\s]+)/i,
    /size[:\s=]+([^\s]+)/i,
  ];

  for (const pattern of sizePatterns) {
    const match = cleanedPrompt.match(pattern);
    if (match) {
      const extractedSize = match[1].trim();
      if (VALID_SIZES.includes(extractedSize)) {
        size = extractedSize;
        cleanedPrompt = cleanedPrompt.replace(pattern, "").trim();
        cleanedPrompt = cleanedPrompt.replace(/\s+/g, " ");
        return { cleanedPrompt, size };
      }
    }
  }

  // 再找單獨出現的 2:3、3:2、1:1
  const loosePattern = /\b(2:3|3:2|1:1)\b/;
  const looseMatch = cleanedPrompt.match(loosePattern);
  if (looseMatch && VALID_SIZES.includes(looseMatch[1])) {
    size = looseMatch[1];
    cleanedPrompt = cleanedPrompt.replace(loosePattern, "").trim();
    cleanedPrompt = cleanedPrompt.replace(/\s+/g, " ");
  }

  return { cleanedPrompt, size };
}

// --- Oak Web Server ---
const app = new Application();
const router = new Router();

// --- 認證中間件 ---
app.use(async (ctx, next) => {
  try {
    // 检查是否缺少token
    if (isMissingToken) {
      ctx.response.status = Status.ServiceUnavailable;
      ctx.response.body = { error: "Server configuration error: KONTEXTFLUX_TOKEN environment variable is not set." };
      return;
    }

    const authHeader = ctx.request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      ctx.response.status = Status.Unauthorized;
      ctx.response.body = { error: "Authentication required. Provide your KontextFlux token in the 'Authorization: Bearer <token>' header." };
      return;
    }
    const token = authHeader.substring(7);
    if (token !== ENV_KONTEXTFLUX_TOKEN) {
      ctx.response.status = Status.Forbidden;
      ctx.response.body = { error: "Invalid KontextFlux token." };
      return;
    }
    const config = await getKontextFluxConfig(token);
    ctx.state.config = config;
    await next();
  } catch (e) {
    console.error("Auth middleware error:", e.message);
    ctx.response.status = Status.Forbidden;
    ctx.response.body = { error: `Invalid or expired KontextFlux token. Details: ${e.message}` };
  }
});

// --- 路由 ---
router.get("/v1/models", (ctx) => {
  ctx.response.body = {
    object: "list",
    data: [{
      id: "kontext-flux",
      object: "model",
      created: Math.floor(Date.now() / 1000),
      owned_by: "kontextflux",
    }],
  };
});

router.post("/v1/chat/completions", async (ctx) => {
  const config = ctx.state.config;
  const requestBody = await ctx.request.body({ type: "json" }).value as ChatRequest;

  if (requestBody.model !== "kontext-flux") {
    ctx.response.status = Status.NotFound;
    ctx.response.body = { error: `Model '${requestBody.model}' not found.` };
    return;
  }

  let prompt = "";
  const imageUrls: string[] = [];

  for (const message of requestBody.messages) {
    if (typeof message.content === 'string') {
      prompt += message.content + " ";
    } else if (Array.isArray(message.content)) {
      for (const part of message.content) {
        if (part.type === 'text' && part.text) {
          prompt += part.text + " ";
        } else if (part.type === 'image_url' && part.image_url?.url) {
          imageUrls.push(part.image_url.url);
        }
      }
    }
  }
  prompt = prompt.trim();

  if (!prompt && imageUrls.length === 0) {
    ctx.response.status = Status.BadRequest;
    ctx.response.body = { error: "Request must contain text prompt or at least one image." };
    return;
  }

  // 解析 prompt 內的 size 參數
  const { cleanedPrompt, size: parsedSize } = parsePromptParameters(prompt);

  // 若 prompt 沒有 size，則用 requestBody.size，否則 fallback "auto"
  let finalSize = parsedSize;
  if (finalSize === "auto" && requestBody.size && VALID_SIZES.includes(requestBody.size)) {
    finalSize = requestBody.size;
  }
  if (!VALID_SIZES.includes(finalSize)) {
    finalSize = "auto";
  }

  try {
    const uploadPromises = imageUrls.map(async (url) => {
      try {
        const imageBytes = await processImageUrl(url);
        if (imageBytes) {
          return await uploadFile(config, imageBytes);
        }
        return null;
      } catch (uploadError) {
        console.error("Image upload error:", uploadError.message);
        return null; // 忽略單張圖片上傳失敗，不中斷整體流程
      }
    });
    const uploadResults = await Promise.all(uploadPromises);
    const uploadedKeys = uploadResults.filter(res => res).map(res => res.key);

    const drawId = await createDrawTask(config, cleanedPrompt, uploadedKeys, finalSize);

    if (requestBody.stream) {
      const stream = new ReadableStream({
        async start(controller) {
          try {
            const ws = await connectToWebSocket(config, drawId);
            const streamId = `chatcmpl-${crypto.randomUUID()}`;
            const created = Math.floor(Date.now() / 1000);
            const send = (data: StreamResponse) => {
              controller.enqueue(`data: ${JSON.stringify(data)}\n\n`);
            };
            send({
              id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
              choices: [{ delta: { role: 'assistant' }, index: 0, finish_reason: null }]
            });
            ws.onmessage = (event) => {
              const msg = JSON.parse(event.data as string);
              if (msg.content?.photo) {
                const finalUrl = msg.content.photo.url;
                send({
                  id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                  choices: [{ delta: { content: `![image](${finalUrl})` }, index: 0, finish_reason: null }]
                });
                send({
                  id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                  choices: [{ delta: {}, index: 0, finish_reason: 'stop' }]
                });
                controller.enqueue('data: [DONE]\n\n');
                ws.close();
                controller.close();
              } else if (msg.content?.progress !== undefined) {
                const progress = msg.content.progress;
                const emoji = progress < 20 ? "🚀" : progress < 40 ? "⚙️" : progress < 60 ? "✨" : progress < 80 ? "🔍" : progress < 100 ? "🎨" : "✅";
                const bar = "█".repeat(Math.floor(progress / 5)) + "░".repeat(20 - Math.floor(progress / 5));
                const reasoningText = `${emoji} 图像生成进度 |${bar}| ${progress}%\n`;
                send({
                  id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                  choices: [{ delta: { reasoning_content: reasoningText }, index: 0, finish_reason: null }]
                });
              }
            };
            ws.onclose = () => {
              if (controller.desiredSize !== null) {
                controller.close();
              }
            };
            ws.onerror = (err) => {
              console.error("WebSocket error:", err.message);
              controller.error(new Error("WebSocket connection failed"));
            };
          } catch (streamError) {
            console.error("Stream error:", streamError.message);
            controller.error(streamError);
          }
        }
      });
      ctx.response.body = stream;
      ctx.response.headers.set("Content-Type", "text/event-stream");
      ctx.response.headers.set("Cache-Control", "no-cache");
      ctx.response.headers.set("Connection", "keep-alive");
    } else {
      const finalUrl = await waitForCompletion(config, drawId);
      ctx.response.body = {
        id: `chatcmpl-${crypto.randomUUID()}`,
        object: "chat.completion",
        created: Math.floor(Date.now() / 1000),
        model: requestBody.model,
        choices: [{
          message: { role: "assistant", content: `![image](${finalUrl})` },
          index: 0,
          finish_reason: "stop"
        }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 }
      };
    }
  } catch (e) {
    console.error("Chat completion error:", e.message);
    ctx.response.status = Status.InternalServerError;
    ctx.response.body = { error: `Internal server error: ${e.message}` };
  }
});

app.use(router.routes());
app.use(router.allowedMethods());

// --- WebSocket 連接 ---
async function connectToWebSocket(config: any, drawId: string): Promise<WebSocket> {
  const encryptor = new KontextFluxEncryptor(config);
  const xtx = await encryptor.getXtxHash({ token: config.token, id: drawId });
  const url = `wss://api.kontextflux.com/client/styleAI/checkWs?xtx=${xtx}`;
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.onopen = () => {
      ws.send(JSON.stringify({ token: config.token, id: drawId }));
      resolve(ws);
    };
    ws.onerror = (err) => {
      reject(new Error(`WebSocket connection failed: ${err.message}`));
    };
  });
}

async function waitForCompletion(config: any, drawId: string): Promise<string> {
  const ws = await connectToWebSocket(config, drawId);
  return new Promise((resolve, reject) => {
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data as string);
      if (msg.content?.photo?.url) {
        ws.close();
        resolve(msg.content.photo.url);
      }
    };
    ws.onerror = (err) => reject(new Error(`WebSocket error: ${err.message}`));
    ws.onclose = () => reject(new Error("WebSocket closed before completion."));
  });
}

// --- 啟動服務 ---
console.log("\n--- KontextFlux OpenAI API Adapter (Deno/Oak) ---");
if (isMissingToken) {
  console.log("⚠️ WARNING: KONTEXTFLUX_TOKEN environment variable is not set!");
  console.log("The server will start but all API requests will fail.");
}
console.log("Server listening on http://localhost:8000");
console.log("Endpoints:");
console.log(" GET /v1/models");
console.log(" POST /v1/chat/completions");
console.log("\nAuthentication:");
console.log(" Provide your KontextFlux token in the Authorization header.");
console.log(" Example: curl -H \"Authorization: Bearer YOUR_KONTEXTFLUX_TOKEN\" ...");
console.log("-------------------------------------------------");
try {
  await app.listen({ port: 8000 });
} catch (e) {
  console.error("App listen error:", e.message);
}
