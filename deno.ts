// @deno-types="npm:@types/ws"

import {
  Application,
  Router,
  Status,
} from "https://deno.land/x/oak@v12.6.1/mod.ts";
import md5 from "https://esm.sh/md5@2.3.0";
import { encodeBase64 as encode, decodeBase64 as decode } from "https://deno.land/std@0.217.0/encoding/base64.ts";
import WebSocket from "npm:ws";
import { createHash } from "https://deno.land/std@0.217.0/crypto/mod.ts";

// --- 环境变量读取 ---
const ENV_CLIENT_API_KEYS = Deno.env.get("CLIENT_API_KEYS");
let VALID_CLIENT_KEYS: Set<string> = new Set();

// 初始化客户端 API 密钥
if (ENV_CLIENT_API_KEYS) {
  try {
    const keys = JSON.parse(ENV_CLIENT_API_KEYS);
    VALID_CLIENT_KEYS = new Set(Array.isArray(keys) ? keys : []);
    console.log(`Successfully loaded ${VALID_CLIENT_KEYS.size} client API keys.`);
  } catch (e) {
    console.error("Error parsing CLIENT_API_KEYS:", e.message);
  }
} else {
  console.error("Warning: CLIENT_API_KEYS environment variable is not set.");
}

// --- 类型定义 ---
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
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
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

// --- KontextFluxEncryptor 加密逻辑 ---
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

// --- API 交互函数 ---
async function getKontextFluxConfig() {
  const url = "https://api.kontextflux.com/client/common/getConfig";
  const payload = { token: null, referrer: "" };
  
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { 
        ...COMMON_HEADERS, 
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br, zstd",
      },
      body: JSON.stringify(payload),
    });
    
    if (!response.ok) {
      throw new Error(`Failed to get config, status: ${response.status}`);
    }
    
    const data = await response.json();
    if (!data.data) {
      throw new Error("Failed to retrieve config data.");
    }
    
    console.log("Successfully retrieved KontextFlux config.");
    return data.data;
  } catch (error) {
    console.error("Error getting KontextFlux config:", error.message);
    throw error;
  }
}

async function uploadFile(config: any, imageBytes: Uint8Array, filename: string = "image.png") {
  const url = "https://api.kontextflux.com/client/resource/uploadFile";
  const encryptor = new KontextFluxEncryptor(config);
  const xtx = await encryptor.getXtxHash({});
  
  try {
    const formData = new FormData();
    formData.append("file", new Blob([imageBytes], { type: "image/png" }), filename);
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...COMMON_HEADERS,
        "Accept-Encoding": "gzip, deflate, br, zstd",
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
    
    console.log(`File uploaded successfully with key: ${data.data.key}`);
    return data.data;
  } catch (error) {
    console.error("Error uploading file:", error.message);
    throw error;
  }
}

async function createDrawTask(config: any, prompt: string, keys: string[] = [], size = "auto") {
  const url = "https://api.kontextflux.com/client/styleAI/draw";
  const payload = { keys, prompt, size };
  
  try {
    const encryptor = new KontextFluxEncryptor(config);
    const xtx = await encryptor.getXtxHash(payload);
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...COMMON_HEADERS,
        "Content-Type": "application/json",
        "Accept-Encoding": "gzip, deflate, br, zstd",
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
    
    console.log(`Draw task created with ID: ${data.data.id}`);
    return data.data.id;
  } catch (error) {
    console.error("Error creating draw task:", error.message);
    throw error;
  }
}

async function processImageUrl(imageUrl: string): Promise<Uint8Array | null> {
  try {
    if (imageUrl.startsWith('data:image/')) {
      const b64 = imageUrl.split(',')[1];
      return decode(b64);
    } else if (imageUrl.startsWith('http')) {
      const response = await fetch(imageUrl, {
        headers: { "User-Agent": COMMON_HEADERS["User-Agent"] },
        redirect: "follow",
      });
      if (!response.ok) {
        console.error(`Failed to fetch image from URL: ${imageUrl}, status: ${response.status}`);
        return null;
      }
      const buffer = await response.arrayBuffer();
      return new Uint8Array(buffer);
    }
    console.error(`Unsupported image URL format: ${imageUrl.substring(0, 30)}...`);
    return null;
  } catch (error) {
    console.error(`Error processing image URL: ${error.message}`);
    return null;
  }
}

// --- HMAC 函数 ---
async function hmacSha256(message: string, key: string): Promise<string> {
  try {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const messageData = encoder.encode(message);
    
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    
    const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageData);
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  } catch (error) {
    console.error(`HMAC generation error: ${error.message}`);
    throw error;
  }
}

// --- 去水印功能（改进版）---
async function watermarkRemover(imageUrl: string): Promise<string> {
  console.log(`Starting watermark removal for: ${imageUrl}`);
  
  try {
    // 下载图片
    const response = await fetch(imageUrl, {
      headers: { "User-Agent": COMMON_HEADERS["User-Agent"] }
    });
    
    if (!response.ok) {
      console.error(`Failed to download image for watermark removal, status: ${response.status}`);
      return imageUrl;
    }
    
    const imageBytes = await response.arrayBuffer();
    console.log(`Successfully downloaded image (${imageBytes.byteLength} bytes)`);
    
    // 生成参数
    const pixbClId = Math.floor(Math.random() * 9000000000) + 1000000000;
    const timestamp = new Date().toISOString();
    const xEbgParam = encode(new TextEncoder().encode(timestamp));
    
    const n = "A4nzUYcDOZ";
    const t = `POST/service/public/transformation/v1.0/predictions/wm/remove${timestamp}${pixbClId}`;
    const xEbgSignature = await hmacSha256(t, n);
    
    console.log(`Generated signature for watermark removal request`);
    
    // 上传图片进行去水印
    const uploadUrl = "https://api.watermarkremover.io/service/public/transformation/v1.0/predictions/wm/remove";
    const formData = new FormData();
    formData.append("input.image", new Blob([imageBytes], { type: "image/png" }), "image.png");
    formData.append("input.rem_text", "false");
    formData.append("input.rem_logo", "false");
    formData.append("retention", "1d");
    
    const uploadResponse = await fetch(uploadUrl, {
      method: "POST",
      headers: {
        "User-Agent": COMMON_HEADERS["User-Agent"],
        "Accept": "application/json, text/plain, */*",
        "x-ebg-signature": xEbgSignature,
        "pixb-cl-id": pixbClId.toString(),
        "x-ebg-param": xEbgParam,
        "origin": "https://www.watermarkremover.io",
        "referer": "https://www.watermarkremover.io/",
      },
      body: formData,
    });
    
    if (!uploadResponse.ok) {
      console.error(`Watermark removal upload failed, status: ${uploadResponse.status}`);
      return imageUrl;
    }
    
    const uploadResult = await uploadResponse.json();
    const resultId = uploadResult._id;
    
    console.log(`Watermark removal task created with ID: ${resultId}`);
    
    // 轮询结果，增加重试和超时机制
    const resultUrl = `https://api.watermarkremover.io/service/public/transformation/v1.0/predictions/${resultId}`;
    const maxAttempts = 30;
    const pollingInterval = 1000; // 1秒
    
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        console.log(`Polling watermark removal result (attempt ${attempt + 1}/${maxAttempts})`);
        
        await new Promise(resolve => setTimeout(resolve, pollingInterval));
        
        const resultResponse = await fetch(resultUrl, {
          headers: {
            "User-Agent": COMMON_HEADERS["User-Agent"],
            "Accept": "application/json, text/plain, */*",
            "origin": "https://www.watermarkremover.io",
            "referer": "https://www.watermarkremover.io/",
          },
        });
        
        if (!resultResponse.ok) {
          console.error(`Error polling watermark removal result, status: ${resultResponse.status}`);
          continue;
        }
        
        const result = await resultResponse.json();
        console.log(`Watermark removal status: ${result.status}`);
        
        if (result.status === "SUCCESS" && result.output?.[0]) {
          console.log(`Watermark removal completed successfully`);
          return result.output[0];
        }
        
        if (result.status === "FAILED") {
          console.error(`Watermark removal failed`);
          return imageUrl;
        }
      } catch (error) {
        console.error(`Error checking watermark removal status: ${error.message}`);
        // 继续轮询，不中断循环
      }
    }
    
    console.error(`Watermark removal timed out after ${maxAttempts} attempts`);
    return imageUrl;
  } catch (error) {
    console.error(`Watermark removal error: ${error.message}`);
    return imageUrl;
  }
}

// --- 参数解析 ---
const VALID_SIZES = ["auto", "2:3", "3:2", "1:1"];

function parsePromptParameters(prompt: string): { cleanedPrompt: string; size: string } {
  let size = "auto";
  let cleanedPrompt = prompt;

  const sizePatterns = [
    /--size[=\s]+([^\s]+)/i,
    /size[:\s=]+([^\s]+)/i,
    /\bsize[=\s]+([^\s]+)/i,
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

  return { cleanedPrompt, size };
}

// --- Oak Web Server ---
const app = new Application();
const router = new Router();

// --- 认证中间件 ---
app.use(async (ctx, next) => {
  // 跳过健康检查和模型列表端点的认证
  if (ctx.request.url.pathname === "/health" || 
      (ctx.request.url.pathname === "/v1/models" && ctx.request.method === "GET")) {
    await next();
    return;
  }

  try {
    if (VALID_CLIENT_KEYS.size === 0) {
      ctx.response.status = Status.ServiceUnavailable;
      ctx.response.body = { error: "Service unavailable: Client API keys not configured." };
      return;
    }

    const authHeader = ctx.request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      ctx.response.status = Status.Unauthorized;
      ctx.response.body = { error: "API key required in Authorization header." };
      return;
    }
    
    const apiKey = authHeader.substring(7);
    if (!VALID_CLIENT_KEYS.has(apiKey)) {
      ctx.response.status = Status.Forbidden;
      ctx.response.body = { error: "Invalid client API key." };
      return;
    }
    
    await next();
  } catch (e) {
    console.error("Auth middleware error:", e.message);
    ctx.response.status = Status.InternalServerError;
    ctx.response.body = { error: "Authentication error" };
  }
});

// --- 路由 ---
router.get("/health", (ctx) => {
  ctx.response.body = {
    status: "ok",
    timestamp: new Date().toISOString(),
    clientKeysConfigured: VALID_CLIENT_KEYS.size > 0,
  };
});

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
  try {
    const requestBody = await ctx.request.body({ type: "json" }).value as ChatRequest;

    if (requestBody.model !== "kontext-flux") {
      ctx.response.status = Status.NotFound;
      ctx.response.body = { error: `Model '${requestBody.model}' not found.` };
      return;
    }

    if (!requestBody.messages || requestBody.messages.length === 0) {
      ctx.response.status = Status.BadRequest;
      ctx.response.body = { error: "No messages provided in the request." };
      return;
    }

    // 提取 prompt 和图片
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

    // 解析参数
    const { cleanedPrompt, size: parsedSize } = parsePromptParameters(prompt);
    let finalSize = parsedSize !== "auto" ? parsedSize : requestBody.size || "auto";
    
    if (!VALID_SIZES.includes(finalSize)) {
      finalSize = "auto";
    }

    // 获取配置
    console.log("Getting KontextFlux configuration...");
    const config = await getKontextFluxConfig();

    // 处理图片上传
    const uploadedKeys: string[] = [];
    if (imageUrls.length > 0) {
      console.log(`Processing ${imageUrls.length} images for upload...`);
      const uploadPromises = imageUrls.map(async (url, index) => {
        try {
          const imageBytes = await processImageUrl(url);
          if (imageBytes) {
            console.log(`Uploading image ${index + 1}/${imageUrls.length}...`);
            const result = await uploadFile(config, imageBytes, `image_${index}.png`);
            return result.key;
          }
          return null;
        } catch (error) {
          console.error(`Error uploading image ${index + 1}: ${error.message}`);
          return null;
        }
      });
      
      const results = await Promise.all(uploadPromises);
      uploadedKeys.push(...results.filter(key => key !== null));
      console.log(`Successfully uploaded ${uploadedKeys.length}/${imageUrls.length} images`);
    }

    // 创建绘图任务
    console.log(`Creating drawing task with prompt: "${cleanedPrompt || "generate image"}"`);
    const drawId = await createDrawTask(config, cleanedPrompt || "generate image", uploadedKeys, finalSize);

    if (requestBody.stream) {
      console.log(`Starting streaming response for draw task ${drawId}`);
      const stream = new ReadableStream({
        async start(controller) {
          const encoder = new TextEncoder();
          let isClosed = false;
          let ws: WebSocket | null = null;
          let imageUrlReceived: string | null = null; // 用于跟踪是否已收到图像URL
          let processingWatermark = false; // 用于跟踪是否正在处理水印移除
          
          const safeSend = (data: StreamResponse) => {
            if (!isClosed) {
              try {
                controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
              } catch (e) {
                console.error("Error enqueueing data:", e);
              }
            }
          };
          
          const closeStream = () => {
            if (!isClosed) {
              isClosed = true;
              try {
                controller.enqueue(encoder.encode('data: [DONE]\n\n'));
                controller.close();
              } catch (e) {
                console.error("Error closing stream:", e);
              }
              if (ws && ws.readyState === WebSocket.OPEN) {
                try {
                  ws.close();
                } catch (e) {
                  console.error("Error closing WebSocket:", e);
                }
              }
            }
          };
          
          try {
            console.log(`Connecting to WebSocket for task ${drawId}...`);
            ws = await connectToWebSocket(config, drawId);
            console.log(`WebSocket connected for task ${drawId}`);
            
            const streamId = `chatcmpl-${crypto.randomUUID()}`;
            const created = Math.floor(Date.now() / 1000);
            let currentProgress = 0;
            
            // 发送初始消息
            safeSend({
              id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
              choices: [{ delta: { role: 'assistant' }, index: 0, finish_reason: null }]
            });
            
            ws.onmessage = async (event) => {
              if (isClosed) return;
              
              try {
                const msg = JSON.parse(event.data as string);
                console.log(`WebSocket message received for task ${drawId}: ${JSON.stringify(msg).substring(0, 100)}...`);
                
                if (msg.content?.photo) {
                  console.log(`Photo URL received for task ${drawId}`);
                  const originalUrl = msg.content.photo.url;
                  
                  // 重要：保存URL，以便WebSocket关闭时仍能处理
                  imageUrlReceived = originalUrl;
                  
                  // 标记正在处理水印移除
                  processingWatermark = true;
                  
                  try {
                    // 尝试去水印
                    console.log(`Starting watermark removal for task ${drawId}`);
                    const finalUrl = await watermarkRemover(originalUrl);
                    console.log(`Watermark removal completed for task ${drawId}`);
                    
                    // 如果流已关闭，则不再发送
                    if (isClosed) return;
                    
                    processingWatermark = false;
                    
                    safeSend({
                      id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                      choices: [{ delta: { content: `![image](${finalUrl})` }, index: 0, finish_reason: null }]
                    });
                    
                    safeSend({
                      id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                      choices: [{ delta: {}, index: 0, finish_reason: 'stop' }]
                    });
                    
                    closeStream();
                  } catch (watermarkError) {
                    console.error(`Watermark removal failed: ${watermarkError.message}`);
                    
                    // 如果流已关闭，则不再发送
                    if (isClosed) return;
                    
                    processingWatermark = false;
                    
                    // 如果去水印失败，使用原始URL
                    safeSend({
                      id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                      choices: [{ delta: { content: `![image](${originalUrl})` }, index: 0, finish_reason: null }]
                    });
                    
                    safeSend({
                      id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                      choices: [{ delta: {}, index: 0, finish_reason: 'stop' }]
                    });
                    
                    closeStream();
                  }
                } else if (msg.content?.progress !== undefined) {
                  const progress = msg.content.progress;
                  
                  // 避免重复进度更新
                  if (currentProgress >= progress) return;
                  currentProgress = progress;
                  
                  console.log(`Progress update for task ${drawId}: ${progress}%`);
                  
                  const emoji = progress < 20 ? "🚀" : progress < 40 ? "⚙️" : progress < 60 ? "✨" : progress < 80 ? "🔍" : progress < 100 ? "🎨" : "✅";
                  const bar = "█".repeat(Math.floor(progress / 5)) + "░".repeat(20 - Math.floor(progress / 5));
                  const reasoningText = `${emoji} 图像生成进度 |${bar}| ${progress}%\n`;
                  
                  safeSend({
                    id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                    choices: [{ delta: { reasoning_content: reasoningText }, index: 0, finish_reason: null }]
                  });
                }
              } catch (e) {
                console.error(`Error processing WebSocket message for task ${drawId}: ${e.message}`);
              }
            };
            
            ws.onclose = async (event) => {
              console.log(`WebSocket closed for task ${drawId} with code ${event.code}`);
              
              // 关键修改：如果已经收到图像URL但还在处理水印移除，继续处理而不报错
              if (imageUrlReceived && processingWatermark) {
                console.log(`WebSocket closed but image URL was received and watermark removal is in progress. Continuing...`);
                // 水印处理已在onmessage中启动，不需要再次启动
                return;
              }
              
              // 如果已收到图像URL但尚未开始处理水印，则在这里处理
              if (imageUrlReceived && !processingWatermark && !isClosed) {
                console.log(`WebSocket closed but image URL was received. Starting watermark removal.`);
                try {
                  const finalUrl = await watermarkRemover(imageUrlReceived);
                  console.log(`Watermark removal completed after WebSocket closed for task ${drawId}`);
                  
                  safeSend({
                    id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                    choices: [{ delta: { content: `![image](${finalUrl})` }, index: 0, finish_reason: null }]
                  });
                  
                  safeSend({
                    id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                    choices: [{ delta: {}, index: 0, finish_reason: 'stop' }]
                  });
                } catch (error) {
                  console.error(`Error in watermark removal after WebSocket closed: ${error.message}`);
                  // 失败时使用原始URL
                  safeSend({
                    id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                    choices: [{ delta: { content: `![image](${imageUrlReceived})` }, index: 0, finish_reason: null }]
                  });
                  
                  safeSend({
                    id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                    choices: [{ delta: {}, index: 0, finish_reason: 'stop' }]
                  });
                }
                closeStream();
                return;
              }
              
              // 只有在没有收到图片URL时才视为异常关闭
              if (currentProgress < 100 && !isClosed && !imageUrlReceived) {
                console.warn(`WebSocket closed before receiving image URL for task ${drawId}`);
                
                // 发送错误信息并关闭流
                safeSend({
                  id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                  choices: [{ delta: { content: "生成过程中断，请重试。" }, index: 0, finish_reason: 'stop' }]
                });
                closeStream();
              }
            };
            
            ws.onerror = (err) => {
              console.error(`WebSocket error for task ${drawId}:`, err);
              // 如果已经收到图像URL，即使出错也不中断处理
              if (!isClosed && !imageUrlReceived) {
                safeSend({
                  id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                  choices: [{ delta: { content: "生成过程发生错误，请重试。" }, index: 0, finish_reason: 'stop' }]
                });
                closeStream();
              }
            };
            
            // 添加安全保障：如果120秒后仍未完成，强制关闭
            setTimeout(() => {
              if (!isClosed && !imageUrlReceived) {
                console.warn(`Task ${drawId} timed out after 120 seconds`);
                safeSend({
                  id: streamId, created, model: requestBody.model, object: "chat.completion.chunk",
                  choices: [{ delta: { content: "生成超时，请重试。" }, index: 0, finish_reason: 'stop' }]
                });
                closeStream();
              }
            }, 120000);
            
          } catch (streamError) {
            console.error(`Stream initialization error for task ${drawId}:`, streamError);
            if (!isClosed) {
              isClosed = true;
              controller.error(streamError);
            }
          }
        }
      });
      
      ctx.response.body = stream;
      ctx.response.headers.set("Content-Type", "text/event-stream");
      ctx.response.headers.set("Cache-Control", "no-cache");
      ctx.response.headers.set("Connection", "keep-alive");
      ctx.response.headers.set("X-Accel-Buffering", "no");
    } else {
      console.log(`Starting non-streaming response for draw task ${drawId}`);
      try {
        const originalUrl = await waitForCompletion(config, drawId);
        console.log(`Non-streaming task ${drawId} completed, removing watermark...`);
        const finalUrl = await watermarkRemover(originalUrl);
        
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
      } catch (error) {
        console.error(`Error in non-streaming response for task ${drawId}:`, error);
        ctx.response.status = Status.InternalServerError;
        ctx.response.body = { error: `Error generating image: ${error.message}` };
      }
    }
  } catch (e) {
    console.error("Chat completion error:", e);
    ctx.response.status = Status.InternalServerError;
    ctx.response.body = { error: `Internal server error: ${e.message}` };
  }
});

app.use(router.routes());
app.use(router.allowedMethods());

// --- WebSocket 连接 ---
async function connectToWebSocket(config: any, drawId: string): Promise<WebSocket> {
  const encryptor = new KontextFluxEncryptor(config);
  const payload = { token: config.token, id: drawId };
  const xtx = await encryptor.getXtxHash(payload);
  const url = `wss://api.kontextflux.com/client/styleAI/checkWs?xtx=${xtx}`;
  
  return new Promise((resolve, reject) => {
    let connectionAttempt = 0;
    const maxAttempts = 3;
    const attemptConnection = () => {
      connectionAttempt++;
      console.log(`WebSocket connection attempt ${connectionAttempt}/${maxAttempts} for task ${drawId}`);
      
      const ws = new WebSocket(url);
      
      // 设置连接超时
      const connectionTimeout = setTimeout(() => {
        if (ws.readyState !== WebSocket.OPEN) {
          console.error(`WebSocket connection timeout for task ${drawId}`);
          ws.close();
          if (connectionAttempt < maxAttempts) {
            console.log(`Retrying WebSocket connection for task ${drawId}`);
            attemptConnection();
          } else {
            reject(new Error(`WebSocket connection failed after ${maxAttempts} attempts`));
          }
        }
      }, 10000); // 10秒连接超时
      
      ws.onopen = () => {
        clearTimeout(connectionTimeout);
        console.log(`WebSocket opened for task ${drawId}, sending payload`);
        try {
          ws.send(JSON.stringify(payload));
          resolve(ws);
        } catch (error) {
          console.error(`Error sending initial payload for task ${drawId}:`, error);
          ws.close();
          reject(error);
        }
      };
      
      ws.onerror = (err) => {
        clearTimeout(connectionTimeout);
        console.error(`WebSocket connection error for task ${drawId}:`, err);
        if (connectionAttempt < maxAttempts) {
          console.log(`Retrying WebSocket connection for task ${drawId}`);
          setTimeout(attemptConnection, 1000); // 1秒后重试
        } else {
          reject(new Error(`WebSocket connection failed after ${maxAttempts} attempts: ${err.message}`));
        }
      };
    };
    
    attemptConnection();
  });
}

// 修改非流式响应的等待完成函数
async function waitForCompletion(config: any, drawId: string): Promise<string> {
  console.log(`Waiting for completion of task ${drawId} (non-streaming mode)`);
  
  return new Promise((resolve, reject) => {
    let completed = false;
    let connectionClosed = false;
    let imageUrlReceived: string | null = null;
    
    const connectAndListen = async () => {
      try {
        const ws = await connectToWebSocket(config, drawId);
        
        // 设置90秒超时
        const timeout = setTimeout(() => {
          if (!completed && !connectionClosed) {
            console.error(`Task ${drawId} timed out after 90 seconds`);
            try {
              ws.close();
            } catch (e) {
              console.error(`Error closing WebSocket after timeout:`, e);
            }
            // 如果有收到图像URL，即使超时也返回该URL
            if (imageUrlReceived) {
              resolve(imageUrlReceived);
            } else {
              reject(new Error("Task timed out after 90 seconds"));
            }
          }
        }, 90000);
        
        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data as string);
            
            if (msg.content?.photo?.url) {
              completed = true;
              clearTimeout(timeout);
              imageUrlReceived = msg.content.photo.url;
              console.log(`Task ${drawId} completed with image URL`);
              ws.close();
              resolve(imageUrlReceived);
            } else if (msg.content?.progress) {
              console.log(`Task ${drawId} progress: ${msg.content.progress}%`);
            }
          } catch (error) {
            console.error(`Error parsing WebSocket message for task ${drawId}:`, error);
          }
        };
        
        ws.onclose = () => {
          connectionClosed = true;
          clearTimeout(timeout);
          
          if (imageUrlReceived) {
            // 如果已经收到图像URL，即使连接关闭也返回
            if (!completed) {
              console.log(`WebSocket closed but image URL was received for task ${drawId}`);
              completed = true;
              resolve(imageUrlReceived);
            }
          } else if (!completed) {
            console.warn(`WebSocket closed before completion for task ${drawId}`);
            reject(new Error("WebSocket closed before completion"));
          }
        };
        
        ws.onerror = (err) => {
          console.error(`WebSocket error for task ${drawId}:`, err);
          
          if (imageUrlReceived && !completed && !connectionClosed) {
            // 如果已经收到图像URL，即使发生错误也返回
            clearTimeout(timeout);
            completed = true;
            try {
              ws.close();
            } catch (e) {
              console.error(`Error closing WebSocket after error:`, e);
            }
            resolve(imageUrlReceived);
          } else if (!completed && !connectionClosed) {
            clearTimeout(timeout);
            try {
              ws.close();
            } catch (e) {
              console.error(`Error closing WebSocket after error:`, e);
            }
            reject(new Error(`WebSocket error: ${err.message}`));
          }
        };
      } catch (error) {
        console.error(`Error in waitForCompletion for task ${drawId}:`, error);
        // 如果有收到图像URL，即使出错也返回
        if (imageUrlReceived) {
          resolve(imageUrlReceived);
        } else {
          reject(error);
        }
      }
    };
    
    connectAndListen();
  });
}

// --- 启动服务 ---
const port = parseInt(Deno.env.get("PORT") || "8000");

console.log("\n--- KontextFlux OpenAI API Adapter (Deno/Oak) ---");
console.log(`Server listening on port ${port}`);
console.log(`Client API Keys loaded: ${VALID_CLIENT_KEYS.size}`);
console.log("\nEndpoints:");
console.log(" GET  /health");
console.log(" GET  /v1/models");
console.log(" POST /v1/chat/completions");
console.log("\nAuthentication:");
console.log(" Provide your client API key in the Authorization header.");
console.log(" Example: curl -H \"Authorization: Bearer YOUR_CLIENT_API_KEY\" ...");
console.log("-------------------------------------------------");

await app.listen({ port });

