import { serve } from "bun";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "fs";
import { join } from "path";

// ============ 类型定义 ============
interface LLMConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
}

interface Config {
  llm: LLMConfig;
  llmBackup: LLMConfig; // 备用 LLM
  llmSettings: {
    timeout: number;      // 请求超时（毫秒）
    maxRetries: number;   // 最大重试次数
    useBackupOnFail: boolean; // 主 LLM 失败时是否使用备用
  };
  rss: { hours: number; topN: number; language: string };
  telegram: { enabled: boolean; botToken: string; chatId: string; pushCount: number };
  schedule: { enabled: boolean; cron: string };
  admin: { username: string; password: string };
}

interface Article {
  id: string;
  title: string;
  titleZh: string;
  link: string;
  content: string;
  summary: string;
  category: string;
  score: number;
  keywords: string[];
  reason: string;
  summaryMsgId: number | null;
  fullTextMsgId: number | null;
  translatedContent: string | null;
  createdAt: number;
}

interface RSSItem {
  title: string;
  link: string;
  content: string;
  pubDate: Date;
  source: string;
}

// ============ 数据目录 ============
const DATA_DIR = join(import.meta.dir, "data");
const CONFIG_FILE = join(DATA_DIR, "config.json");
const SEEN_FILE = join(DATA_DIR, "seen.json");
const ARTICLES_FILE = join(DATA_DIR, "articles.json");
const HISTORY_FILE = join(DATA_DIR, "history.json");
const LOG_FILE = join(DATA_DIR, "logs.json");

// 确保数据目录存在
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

// ============ 日志系统 ============
const MAX_LOGS = 500; // 最大日志条数
interface LogEntry {
  time: number;
  level: "info" | "warn" | "error";
  message: string;
}

let logsCache: LogEntry[] = [];

function initLogs() {
  try {
    if (existsSync(LOG_FILE)) {
      logsCache = JSON.parse(readFileSync(LOG_FILE, "utf-8"));
    }
  } catch (e) {
    logsCache = [];
  }
}

function addLog(level: LogEntry["level"], message: string) {
  const entry: LogEntry = { time: Date.now(), level, message };
  logsCache.push(entry);
  
  // 限制日志数量
  if (logsCache.length > MAX_LOGS) {
    logsCache = logsCache.slice(-MAX_LOGS);
  }
  
  // 异步保存（不阻塞）
  try {
    writeFileSync(LOG_FILE, JSON.stringify(logsCache));
  } catch (e) {}
}

function log(message: string) {
  console.log(message);
  addLog("info", message);
}

function logWarn(message: string) {
  console.warn(message);
  addLog("warn", message);
}

function logError(message: string) {
  console.error(message);
  addLog("error", message);
}

// 初始化日志
initLogs();

// ============ 默认配置 ============
const DEFAULT_CONFIG: Config = {
  llm: { baseUrl: "https://api.openai.com/v1", apiKey: "", model: "gpt-4o" },
  llmBackup: { baseUrl: "", apiKey: "", model: "" }, // 备用 LLM（可选）
llmSettings: {
    timeout: 120000,       // 120秒超时
    maxRetries: 2,         // 最多重试2次
    useBackupOnFail: true, // 主 LLM 失败时使用备用
  },
  rss: { hours: 48, topN: 15, language: "zh" },
  telegram: { enabled: false, botToken: "", chatId: "", pushCount: 10 },
  schedule: { enabled: false, cron: "0 8 * * *" },
  admin: { username: "admin", password: "admin123" },
};

// ============ JWT 认证 ============
const JWT_SECRET = process.env.JWT_SECRET || "ai-daily-secret-" + Math.random().toString(36).slice(2);
const TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24小时

interface TokenPayload {
  username: string;
  exp: number;
}

function base64UrlEncode(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(str: string): string {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

function generateToken(username: string): string {
  const header = { alg: "HS256", typ: "JWT" };
  const payload: TokenPayload = { username, exp: Date.now() + TOKEN_EXPIRY };
  
  const headerB64 = base64UrlEncode(JSON.stringify(header));
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  
  // 简化签名（生产环境应使用 crypto.subtle）
  const signature = base64UrlEncode(
    Array.from(headerB64 + "." + payloadB64 + JWT_SECRET)
      .reduce((hash, char) => ((hash << 5) - hash + char.charCodeAt(0)) | 0, 0)
      .toString(16)
  );
  
  return `${headerB64}.${payloadB64}.${signature}`;
}

function verifyToken(token: string): TokenPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const payload: TokenPayload = JSON.parse(base64UrlDecode(parts[1]));
    if (payload.exp < Date.now()) return null;
    
    // 验证签名
    const expectedSig = base64UrlEncode(
      Array.from(parts[0] + "." + parts[1] + JWT_SECRET)
        .reduce((hash, char) => ((hash << 5) - hash + char.charCodeAt(0)) | 0, 0)
        .toString(16)
    );
    
    if (parts[2] !== expectedSig) return null;
    return payload;
  } catch {
    return null;
  }
}

function getTokenFromRequest(req: Request): string | null {
  // 从 Authorization header 获取
  const auth = req.headers.get("Authorization");
  if (auth?.startsWith("Bearer ")) {
    return auth.slice(7);
  }
  // 从 Cookie 获取
  const cookie = req.headers.get("Cookie");
  if (cookie) {
    const match = cookie.match(/token=([^;]+)/);
    if (match) return match[1];
  }
  return null;
}

function isAuthenticated(req: Request): boolean {
  const token = getTokenFromRequest(req);
  if (!token) return false;
  return verifyToken(token) !== null;
}

// RSS 源配置
interface RSSFeed {
  url: string;
  source: string;
  enabled: boolean;
}

// 从外部文件加载默认 RSS 源
const DEFAULT_RSS_FILE = join(import.meta.dir, "rss-feeds.json");
const RSS_FILE = join(DATA_DIR, "rss.json");

function getDefaultRSSFeeds(): RSSFeed[] {
  if (existsSync(DEFAULT_RSS_FILE)) {
    try {
      return JSON.parse(readFileSync(DEFAULT_RSS_FILE, "utf-8"));
  } catch (e) {
    logError("读取默认 RSS 配置失败: " + (e as Error).message);
  }
  }
  // 最小回退列表
  return [
    { url: "https://lobste.rs/rss", source: "Lobste.rs", enabled: true },
    { url: "https://hnrss.org/newest?points=100", source: "HackerNews", enabled: true },
  ];
}

function getRSSFeeds(): RSSFeed[] {
  return loadJSON<RSSFeed[]>(RSS_FILE, getDefaultRSSFeeds());
}

// ============ 工具函数 ============
function loadJSON<T>(file: string, defaultValue: T): T {
  try {
    if (existsSync(file)) return JSON.parse(readFileSync(file, "utf-8"));
  } catch {}
  return defaultValue;
}

function saveJSON(file: string, data: any) {
  writeFileSync(file, JSON.stringify(data, null, 2));
}

// 清理过期的 seen 记录（保留最近30天的URL）
function cleanupSeenData() {
  const seen = loadJSON<string[]>(SEEN_FILE, []);
  const MAX_SEEN = 5000; // 最多保留5000条
  
  if (seen.length > MAX_SEEN) {
    const trimmed = seen.slice(-MAX_SEEN); // 保留最新的
    saveJSON(SEEN_FILE, trimmed);
    log(`🧹 清理 seen.json: ${seen.length} → ${trimmed.length}`);
  }
}

// 清理过期文章（保留最近7天）
function cleanupArticles() {
  const articles = loadJSON<Record<string, Article>>(ARTICLES_FILE, {});
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  
  const cleaned: Record<string, Article> = {};
  let removed = 0;
  
  for (const [id, article] of Object.entries(articles)) {
    if (article.createdAt > cutoff) {
      cleaned[id] = article;
    } else {
      removed++;
    }
  }
  
  if (removed > 0) {
    saveJSON(ARTICLES_FILE, cleaned);
    log(`🧹 清理 articles.json: 移除 ${removed} 篇过期文章`);
  }
}

function generateId(): string {
  return Math.random().toString(36).slice(2, 10);
}

function htmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&/g, "&")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, '"')
    .replace(/\s+/g, " ")
    .trim();
}

// ============ RSS 解析 ============
async function fetchRSS(feedUrl: string, source: string): Promise<RSSItem[]> {
  try {
    const res = await fetch(feedUrl, {
      headers: { "User-Agent": "AI-Daily-Digest/1.0" },
    });
    const xml = await res.text();
    const items: RSSItem[] = [];

    // 简单 XML 解析
    const itemMatches = xml.match(/<item[\s\S]*?<\/item>/gi) || 
                        xml.match(/<entry[\s\S]*?<\/entry>/gi) || [];

    for (const item of itemMatches) {
      const title = item.match(/<title[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/title>/i)?.[1] || "";
      const link = item.match(/<link[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/link>/i)?.[1] ||
                   item.match(/<link[^>]*href="([^"]+)"/i)?.[1] || "";
      const content = item.match(/<content[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/content/i)?.[1] ||
                      item.match(/<description[^>]*>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/description>/i)?.[1] || "";
      const pubDate = item.match(/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/i)?.[1] ||
                      item.match(/<published[^>]*>([\s\S]*?)<\/published>/i)?.[1] ||
                      item.match(/<updated[^>]*>([\s\S]*?)<\/updated>/i)?.[1] || "";

      if (title && link) {
        items.push({
          title: htmlToText(title),
          link: link.trim(),
          content: htmlToText(content).slice(0, 5000),
          pubDate: new Date(pubDate),
          source,
        });
      }
    }
    return items;
  } catch (e) {
    logError(`RSS fetch error [${source}]: ${(e as Error).message}`);
    return [];
  }
}

async function fetchAllFeeds(hours: number): Promise<RSSItem[]> {
  const cutoff = Date.now() - hours * 60 * 60 * 1000;
  const feeds = getRSSFeeds().filter(f => f.enabled);
  const results = await Promise.all(
    feeds.map((f) => fetchRSS(f.url, f.source))
  );
  return results
    .flat()
    .filter((item) => item.pubDate.getTime() > cutoff)
    .sort((a, b) => b.pubDate.getTime() - a.pubDate.getTime());
}

// ============ AI 调用 ============
// 单次 LLM 请求（带超时）
async function callLLMOnce(llmConfig: LLMConfig, prompt: string, timeout: number): Promise<string> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);
  
  try {
    const res = await fetch(`${llmConfig.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${llmConfig.apiKey}`,
      },
      body: JSON.stringify({
        model: llmConfig.model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.7,
      }),
      signal: controller.signal,
    });
    
    if (!res.ok) {
      throw new Error(`API 返回 ${res.status}: ${res.statusText}`);
    }
    
    const data = await res.json();
    const content = data.choices?.[0]?.message?.content;
    if (!content) {
      throw new Error("API 返回空内容");
    }
    return content;
  } finally {
    clearTimeout(timeoutId);
  }
}

// 带重试和备用切换的 LLM 调用
async function callLLM(config: Config, prompt: string): Promise<string> {
  const settings = config.llmSettings || DEFAULT_CONFIG.llmSettings;
  const timeout = settings.timeout || 60000;
  const maxRetries = settings.maxRetries || 2;
  
  // 尝试主 LLM
  if (config.llm.apiKey) {
    for (let i = 0; i <= maxRetries; i++) {
      try {
        log(`🤖 调用主 LLM (尝试 ${i + 1}/${maxRetries + 1})...`);
        return await callLLMOnce(config.llm, prompt, timeout);
      } catch (e: any) {
        logError(`主 LLM 失败 (${i + 1}/${maxRetries + 1}): ${e.message}`);
        if (i < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * (i + 1))); // 递增延迟
        }
      }
    }
  }
  
  // 主 LLM 失败，尝试备用 LLM
  if (settings.useBackupOnFail && config.llmBackup?.apiKey) {
    log("🔄 切换到备用 LLM...");
    for (let i = 0; i <= maxRetries; i++) {
      try {
        log(`🤖 调用备用 LLM (尝试 ${i + 1}/${maxRetries + 1})...`);
        return await callLLMOnce(config.llmBackup, prompt, timeout);
      } catch (e: any) {
        logError(`备用 LLM 失败 (${i + 1}/${maxRetries + 1}): ${e.message}`);
        if (i < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * (i + 1)));
        }
      }
    }
  }
  
  throw new Error("所有 LLM 调用均失败");
}

async function scoreAndSummarize(
  config: Config,
  item: RSSItem
): Promise<{
  score: number;
  category: string;
  titleZh: string;
  summary: string;
  keywords: string[];
  reason: string;
} | null> {
  const prompt = `分析以下技术文章，返回 JSON 格式：

标题: ${item.title}
来源: ${item.source}
内容: ${item.content.slice(0, 3000)}

返回格式（只返回JSON，不要其他内容）：
{
  "score": 评分1-10,
  "category": "分类(engineering/ai/tools/other)",
  "titleZh": "中文标题",
  "summary": "4-6句中文摘要",
  "keywords": ["关键词1", "关键词2", "关键词3"],
  "reason": "一句话推荐理由"
}`;

  try {
    const result = await callLLM(config, prompt);
    const json = result.match(/\{[\s\S]*\}/)?.[0];
    if (json) return JSON.parse(json);
  } catch (e) {
    logError("AI scoring error: " + (e as Error).message);
  }
  return null;
}

// 清理原文 HTML，为翻译准备干净的文本
function cleanContentForTranslation(html: string): string {
  return html
    // 保留代码块结构
    .replace(/<pre[^>]*>([\s\S]*?)<\/pre>/gi, '\n```\n$1\n```\n')
    .replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, '`$1`')
    // 块级元素转换为换行
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<\/tr>/gi, '\n')
    .replace(/<\/h[1-6]>/gi, '\n\n')
    .replace(/<hr\s*\/?>/gi, '\n---\n')
    // 移除所有其他标签
    .replace(/<[^>]+>/g, '')
    // HTML 实体解码
    .replace(/&/g, '&')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/'/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
    // 清理空白
    .replace(/\r\n/g, '\n')
    .replace(/\t/g, ' ')
    .replace(/ +/g, ' ')
    .replace(/\n /g, '\n')
    .replace(/ \n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// 从网页 URL 抓取文章正文内容
async function fetchArticleContent(url: string): Promise<string> {
  try {
    log(`🌐 抓取网页内容: ${url}`);
    const res = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
    
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    
    const html = await res.text();
    
    // 尝试提取正文内容
    let content = "";
    
    // 优先提取 <article> 标签
    const articleMatch = html.match(/<article[^>]*>([\s\S]*?)<\/article>/i);
    if (articleMatch) {
      content = articleMatch[1];
    }
    
    // 尝试 <main> 标签
    if (!content || content.length < 500) {
      const mainMatch = html.match(/<main[^>]*>([\s\S]*?)<\/main>/i);
      if (mainMatch && mainMatch[1].length > content.length) {
        content = mainMatch[1];
      }
    }
    
    // 尝试常见的内容容器
    if (!content || content.length < 500) {
      const contentPatterns = [
        /<div[^>]*class="[^"]*(?:post-content|article-content|entry-content|content-body|post-body|article-body)[^"]*"[^>]*>([\s\S]*?)<\/div>/i,
        /<div[^>]*id="[^"]*(?:content|article|post|main)[^"]*"[^>]*>([\s\S]*?)<\/div>/i,
      ];
      for (const pattern of contentPatterns) {
        const match = html.match(pattern);
        if (match && match[1].length > (content?.length || 0)) {
          content = match[1];
        }
      }
    }
    
    // 最后尝试 <body>
    if (!content || content.length < 500) {
      const bodyMatch = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i);
      if (bodyMatch) {
        // 移除脚本、样式、导航等
        content = bodyMatch[1]
          .replace(/<script[\s\S]*?<\/script>/gi, '')
          .replace(/<style[\s\S]*?<\/style>/gi, '')
          .replace(/<nav[\s\S]*?<\/nav>/gi, '')
          .replace(/<header[\s\S]*?<\/header>/gi, '')
          .replace(/<footer[\s\S]*?<\/footer>/gi, '')
          .replace(/<aside[\s\S]*?<\/aside>/gi, '')
          .replace(/<!--[\s\S]*?-->/g, '');
      }
    }
    
    // 清理并转换为文本
    const cleanedContent = cleanContentForTranslation(content);
    log(`🌐 抓取完成，内容长度: ${cleanedContent.length}`);
    
    return cleanedContent;
  } catch (e) {
    logError(`🌐 网页抓取失败: ${(e as Error).message}`);
    return "";
  }
}

async function translateFullText(config: Config, content: string): Promise<string> {
  // 先清理 HTML，得到干净的文本
  const cleanContent = cleanContentForTranslation(content);
  log(`📄 原文长度: ${content.length}, 清理后: ${cleanContent.length}`);
  
  // 支持更长内容翻译（分段处理超长文章）
  const maxChunk = 25000;  // 留出 prompt 空间
  const settings = config.llmSettings || DEFAULT_CONFIG.llmSettings;
  const baseTimeout = settings.timeout || 60000;
  const translateTimeout = Math.max(baseTimeout * 3, 180000);

  const translateConfig: Config = {
    ...config,
    llmSettings: {
      ...settings,
      timeout: translateTimeout,
    },
  };

  const translatePrompt = (text: string) => `将以下英文技术文章翻译成流畅的中文。要求：
1. 保持技术术语准确
2. 保留代码块格式
3. 直接返回翻译结果，不要添加任何说明或前缀

${text}`;

  // 如果内容不太长，直接翻译
  if (cleanContent.length <= maxChunk) {
    return await callLLM(translateConfig, translatePrompt(cleanContent));
  }

  // 超长内容分段翻译
  log(`📄 文章较长(${cleanContent.length}字符)，分段翻译...`);
  const parts: string[] = [];
  let remaining = cleanContent;
  let partNum = 1;
  
  while (remaining.length > 0) {
    let chunk: string;
    if (remaining.length <= maxChunk) {
      chunk = remaining;
      remaining = "";
    } else {
      // 尝试在段落处分割
      let splitPos = remaining.lastIndexOf('\n\n', maxChunk);
      if (splitPos < maxChunk / 2) splitPos = remaining.lastIndexOf('. ', maxChunk);
      if (splitPos < maxChunk / 2) splitPos = remaining.lastIndexOf('\n', maxChunk);
      if (splitPos < maxChunk / 2) splitPos = maxChunk;
      chunk = remaining.slice(0, splitPos);
      remaining = remaining.slice(splitPos).trim();
    }
    
    log(`📄 翻译第 ${partNum} 部分 (${chunk.length} 字符)...`);
    const translated = await callLLM(translateConfig, translatePrompt(chunk));
    parts.push(translated);
    partNum++;
  }
  
  log(`📄 分段翻译完成，共 ${parts.length} 部分`);
  return parts.join('\n\n');
}

// ============ Telegram ============
async function sendTelegram(
  config: Config,
  text: string,
  replyMarkup?: any
): Promise<number | null> {
  if (!config.telegram.enabled || !config.telegram.botToken) return null;

  try {
    const res = await fetch(
      `https://api.telegram.org/bot${config.telegram.botToken}/sendMessage`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: config.telegram.chatId,
          text,
          parse_mode: "HTML",
          reply_markup: replyMarkup,
        }),
      }
    );
    const data = await res.json();
    return data.result?.message_id || null;
  } catch (e) {
    logError("Telegram error: " + (e as Error).message);
    return null;
  }
}

function formatSummaryMessage(article: Article): { text: string; markup: any } {
  const categoryEmoji: Record<string, string> = {
    engineering: "⚙️",
    ai: "🤖",
    tools: "🛠️",
    other: "📰",
  };

  const stars = "★".repeat(Math.round(article.score / 2)) + "☆".repeat(5 - Math.round(article.score / 2));
  const emoji = categoryEmoji[article.category] || "📰";
  
  // 手机端优化格式 - 标题突出显示
  const text = `${emoji} <b>${article.titleZh}</b>
<i>${article.title}</i>
${stars} ${article.score}/10

${article.summary}

💡 ${article.reason}

#${article.keywords.slice(0, 4).join(" #")}`;

  const markup = {
    inline_keyboard: [
      [
        { text: "📖 中文全文", callback_data: `read_${article.id}` },
        { text: "🔗 原文", url: article.link },
      ],
    ],
  };

  return { text, markup };
}

// 分段发送长消息的辅助函数
function splitLongText(text: string, maxLen: number = 4000): string[] {
  if (text.length <= maxLen) return [text];
  
  const parts: string[] = [];
  let remaining = text;
  
  while (remaining.length > 0) {
    if (remaining.length <= maxLen) {
      parts.push(remaining);
      break;
    }
    
    // 尝试在段落处分割
    let splitPos = remaining.lastIndexOf('\n\n', maxLen);
    if (splitPos < maxLen / 2) {
      // 如果段落分割点太靠前，尝试在句号处分割
      splitPos = remaining.lastIndexOf('。', maxLen);
    }
    if (splitPos < maxLen / 2) {
      // 如果还是太靠前，尝试在空格处分割
      splitPos = remaining.lastIndexOf(' ', maxLen);
    }
    if (splitPos < maxLen / 2) {
      // 最后手段：强制在 maxLen 处分割
      splitPos = maxLen;
    }
    
    parts.push(remaining.slice(0, splitPos));
    remaining = remaining.slice(splitPos).trim();
  }
  
  return parts;
}

// 清理 HTML 标签，转换为纯文本
function sanitizeHtml(text: string): string {
  return text
    // 先处理块级标签，转换为换行
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<\/li>/gi, '\n')
    .replace(/<\/tr>/gi, '\n')
    .replace(/<\/h[1-6]>/gi, '\n\n')
    .replace(/<hr\s*\/?>/gi, '\n───\n')
    // 移除所有其他 HTML 标签
    .replace(/<[^>]+>/g, '')
    // HTML 实体解码（顺序很重要：& 必须最先处理）
    .replace(/&/g, '&')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/'/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)))
    // 清理多余空白
    .replace(/\r\n/g, '\n')
    .replace(/\t/g, ' ')
    .replace(/ +/g, ' ')
    .replace(/\n /g, '\n')
    .replace(/ \n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// 格式化全文消息 - 返回多条消息（支持长文分段）
// chatInfo 可选，用于生成直接跳转的返回摘要按钮
function formatFullTextMessages(
  article: Article,
  chatInfo?: { username?: string; type?: string; id?: number | string }
): { texts: string[]; markup: any } {
  const rawContent = article.translatedContent || "翻译中...";
  
  // 清理 HTML 并格式化内容
  const content = sanitizeHtml(rawContent);
  const formattedContent = content
    .split('\n\n')
    .map(p => p.trim())
    .filter(p => p)
    .join('\n\n');

  // 头部 - 简洁紧凑
  const header = `📖 <b>${article.titleZh}</b>
<i>${article.title}</i>

───────────────`;

  // 尾部 - 简洁
  const tags = article.keywords?.slice(0, 4).map(k => `#${k}`).join(" ") || "";
  const footer = `───────────────
${tags}`;

  // 构建按钮 - 单行显示
  const inlineKeyboard: any[][] = [];
  const buttons: any[] = [];
  
  // 返回摘要按钮 - 尝试生成直接跳转 URL
  if (article.summaryMsgId && chatInfo) {
    let jumpUrl = "";
    if (chatInfo.username) {
      jumpUrl = `https://t.me/${chatInfo.username}/${article.summaryMsgId}`;
    } else if ((chatInfo.type === "supergroup" || chatInfo.type === "channel") && chatInfo.id) {
      const shortChatId = String(chatInfo.id).replace(/^-100/, "");
      jumpUrl = `https://t.me/c/${shortChatId}/${article.summaryMsgId}`;
    }
    if (jumpUrl) {
      buttons.push({ text: "↩️ 返回", url: jumpUrl });
    }
  }
  
  buttons.push({ text: "🔗 原文", url: article.link });
  inlineKeyboard.push(buttons);
  const finalMarkup = { inline_keyboard: inlineKeyboard };

  // 检查是否需要分段
  const fullText = `${header}\n\n${formattedContent}\n\n${footer}`;
  
  if (fullText.length <= 4000) {
    return { texts: [fullText], markup: finalMarkup };
  }
  
  // 需要分段发送
  const contentParts = splitLongText(formattedContent, 3800);
  const texts: string[] = [];
  
  // 第一条：标题 + 第一部分内容
  texts.push(`${header}\n\n${contentParts[0]}${contentParts.length > 1 ? '\n\n<i>[ 1/${contentParts.length} ]</i>' : ''}`);
  
  // 中间部分
  for (let i = 1; i < contentParts.length - 1; i++) {
    texts.push(`${contentParts[i]}\n\n<i>[ ${i + 1}/${contentParts.length} ]</i>`);
  }
  
  // 最后一条：最后部分 + 尾部
  if (contentParts.length > 1) {
    texts.push(`${contentParts[contentParts.length - 1]}\n\n${footer}`);
  }

  return { texts, markup: finalMarkup };
}

// 保持旧函数兼容性（用于单条消息场景）
function formatFullTextMessage(
  article: Article
): { text: string; markup: any } {
  const { texts, markup } = formatFullTextMessages(article);
  return { text: texts[0], markup };
}

// ============ 核心任务 ============
let isDigestRunning = false;

async function runDigest(): Promise<{ success: boolean; message: string; count: number }> {
  // 防止重复执行
  if (isDigestRunning) {
    return { success: false, message: "任务正在运行中，请稍后再试", count: 0 };
  }
  isDigestRunning = true;

  try {
    const config = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
    const seen = loadJSON<string[]>(SEEN_FILE, []);
    const articles = loadJSON<Record<string, Article>>(ARTICLES_FILE, {});

    if (!config.llm.apiKey) {
      return { success: false, message: "请先配置 LLM API Key", count: 0 };
    }

  log("📡 抓取 RSS...");
  const items = await fetchAllFeeds(config.rss.hours);
  log(`获取到 ${items.length} 篇文章`);

  // 去重
  const newItems = items.filter((item) => !seen.includes(item.link));
  log(`去重后 ${newItems.length} 篇新文章`);

  if (newItems.length === 0) {
    return { success: true, message: "没有新文章", count: 0 };
  }

  // AI 评分
  const toProcess = newItems.slice(0, config.rss.topN * 2);
  log(`🤖 AI 评分中... (共 ${toProcess.length} 篇)`);
  const scored: { item: RSSItem; result: NonNullable<Awaited<ReturnType<typeof scoreAndSummarize>>> }[] = [];

  for (let i = 0; i < toProcess.length; i++) {
    const item = toProcess[i];
    log(`📝 [${i + 1}/${toProcess.length}] ${item.title.slice(0, 50)}...`);
    try {
      const result = await scoreAndSummarize(config, item);
      if (result && result.score >= 6) {
        scored.push({ item, result });
        log(`   ✅ 得分: ${result.score}`);
      } else if (result) {
        log(`   ⏭️ 得分: ${result.score} (跳过)`);
      } else {
        log(`   ❌ 评分失败`);
      }
    } catch (e: any) {
      logError(`   ❌ 错误: ${e.message}`);
    }
    // 避免 API 限流
    await new Promise((r) => setTimeout(r, 500));
  }

  // 排序取 TopN
  scored.sort((a, b) => b.result.score - a.result.score);
  const topArticles = scored.slice(0, config.telegram.pushCount);

  log(`筛选出 ${topArticles.length} 篇高质量文章`);

  // 推送
  const newArticles: Article[] = [];
  for (const { item, result } of topArticles) {
    const id = generateId();
    const article: Article = {
      id,
      title: item.title,
      titleZh: result.titleZh,
      link: item.link,
      content: item.content,
      summary: result.summary,
      category: result.category,
      score: result.score,
      keywords: result.keywords,
      reason: result.reason,
      summaryMsgId: null,
      fullTextMsgId: null,
      translatedContent: null,
      createdAt: Date.now(),
    };

    // 发送 Telegram
    const { text, markup } = formatSummaryMessage(article);
    const msgId = await sendTelegram(config, text, markup);
    article.summaryMsgId = msgId;

    // 保存
    articles[id] = article;
    seen.push(item.link);
    newArticles.push(article);

    await new Promise((r) => setTimeout(r, 300));
  }

  // 保存数据
  saveJSON(ARTICLES_FILE, articles);
  saveJSON(SEEN_FILE, seen);

  // 更新历史
  const history = loadJSON<any[]>(HISTORY_FILE, []);
  history.unshift({
    date: new Date().toISOString().split("T")[0],
    count: newArticles.length,
    articles: newArticles.map((a) => ({ id: a.id, title: a.titleZh, score: a.score })),
  });
  saveJSON(HISTORY_FILE, history.slice(0, 30)); // 保留30天

    return { success: true, message: `成功处理 ${newArticles.length} 篇文章`, count: newArticles.length };
  } catch (error: any) {
    logError("❌ 任务执行出错: " + error.message);
    return { success: false, message: `执行出错: ${error.message}`, count: 0 };
  } finally {
    isDigestRunning = false;
  }
}

// 发送多条Telegram消息（用于长文分段）
async function sendTelegramMessages(
  config: Config,
  texts: string[],
  finalMarkup?: any
): Promise<number | null> {
  let lastMsgId: number | null = null;
  
  for (let i = 0; i < texts.length; i++) {
    const isLast = i === texts.length - 1;
    const markup = isLast ? finalMarkup : undefined;
    
    lastMsgId = await sendTelegram(config, texts[i], markup);
    
    // 防止发送过快
    if (!isLast) {
      await new Promise(r => setTimeout(r, 200));
    }
  }
  
  return lastMsgId;
}

// 发送消息到指定聊天（用于 webhook 回调）
async function sendToChat(
  botToken: string,
  chatId: number | string,
  text: string,
  replyMarkup?: any
): Promise<number | null> {
  try {
    const res = await fetch(
      `https://api.telegram.org/bot${botToken}/sendMessage`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          chat_id: chatId,
          text,
          parse_mode: "HTML",
          reply_markup: replyMarkup,
        }),
      }
    );
    const data = await res.json();
    if (!data.ok) {
      logError(`Telegram sendToChat 失败: ${JSON.stringify(data)}`);
    }
    return data.result?.message_id || null;
  } catch (e) {
    logError("Telegram sendToChat error: " + (e as Error).message);
    return null;
  }
}

// 发送多条消息到指定聊天
async function sendMultipleToChat(
  botToken: string,
  chatId: number | string,
  texts: string[],
  finalMarkup?: any
): Promise<number | null> {
  let lastMsgId: number | null = null;
  
  for (let i = 0; i < texts.length; i++) {
    const isLast = i === texts.length - 1;
    const markup = isLast ? finalMarkup : undefined;
    
    lastMsgId = await sendToChat(botToken, chatId, texts[i], markup);
    
    if (!isLast) {
      await new Promise(r => setTimeout(r, 200));
    }
  }
  
  return lastMsgId;
}

// ============ Telegram Webhook 处理 ============
async function handleTelegramCallback(callbackQuery: any): Promise<void> {
  const config = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
  const articles = loadJSON<Record<string, Article>>(ARTICLES_FILE, {});
  const data = callbackQuery.data as string;
  const chatId = callbackQuery.message?.chat?.id;
  
  log(`📨 收到回调: data=${data}, chatId=${chatId}`);

  if (data.startsWith("read_")) {
    const articleId = data.replace("read_", "");
    const article = articles[articleId];

    if (!article) {
      // 文章不存在，给出提示
      await fetch(
        `https://api.telegram.org/bot${config.telegram.botToken}/answerCallbackQuery`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ 
            callback_query_id: callbackQuery.id,
            text: "❌ 文章不存在或已过期",
            show_alert: true,
          }),
        }
      );
      return;
    }

    // 应答回调（正在处理）
    await fetch(
      `https://api.telegram.org/bot${config.telegram.botToken}/answerCallbackQuery`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          callback_query_id: callbackQuery.id,
          text: "⏳ 正在加载...",
        }),
      }
    );

  // 如果还没翻译，先翻译
  if (!article.translatedContent) {
    // 发送"翻译中"提示 - 简洁格式
    const loadingMsg = `⏳ <b>${article.titleZh}</b>\n\n正在翻译...`;
    const loadingMsgId = await sendToChat(config.telegram.botToken, chatId, loadingMsg);
      log(`📤 发送翻译中提示到 chatId=${chatId}, msgId=${loadingMsgId}`);

      // 翻译（带错误处理）
      try {
        log(`📖 开始翻译文章: ${article.titleZh}`);
        
        // 检查本地内容是否足够，不足则从网页抓取
        let contentToTranslate = article.content;
        const cleanedLocal = cleanContentForTranslation(contentToTranslate);
        
        if (cleanedLocal.length < 500) {
          log(`📄 本地内容太短(${cleanedLocal.length}字符)，从原文链接抓取...`);
          const fetchedContent = await fetchArticleContent(article.link);
          if (fetchedContent.length > cleanedLocal.length) {
            contentToTranslate = fetchedContent;
            // 同时更新文章的 content 字段，下次不用重新抓取
            article.content = fetchedContent;
            log(`📄 抓取成功，内容长度: ${fetchedContent.length}`);
          } else {
            log(`📄 抓取内容仍然较短，使用本地内容`);
          }
        }
        
        article.translatedContent = await translateFullText(config, contentToTranslate);
        log(`✅ 翻译完成: ${article.titleZh}`);
        saveJSON(ARTICLES_FILE, articles);
      } catch (e: any) {
        logError(`❌ 翻译失败: ${e.message}`);
        // 删除加载消息
        if (loadingMsgId) {
          await fetch(
            `https://api.telegram.org/bot${config.telegram.botToken}/deleteMessage`,
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                chat_id: chatId,
                message_id: loadingMsgId,
              }),
            }
          );
        }
        // 发送错误提示到回调消息所在的聊天
        await sendToChat(config.telegram.botToken, chatId, `❌ <b>翻译失败</b>\n\n${article.titleZh}\n\n原因: ${e.message}\n\n请稍后重试或检查 LLM 配置。`);
        return;
      }

      // 删除加载消息
      if (loadingMsgId) {
        await fetch(
          `https://api.telegram.org/bot${config.telegram.botToken}/deleteMessage`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              chat_id: chatId,
              message_id: loadingMsgId,
            }),
          }
        );
      }
    }

    // 获取聊天信息用于生成返回摘要按钮
    let chatInfo: { username?: string; type?: string; id?: number | string } | undefined;
    try {
      const chatInfoRes = await fetch(
        `https://api.telegram.org/bot${config.telegram.botToken}/getChat`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: chatId }),
        }
      );
      const chatInfoData = await chatInfoRes.json();
      if (chatInfoData.ok) {
        chatInfo = {
          username: chatInfoData.result.username,
          type: chatInfoData.result.type,
          id: chatId,
        };
        log(`📋 获取聊天信息成功: username=${chatInfo.username}, type=${chatInfo.type}`);
      }
    } catch (e) {
      logError("获取聊天信息失败: " + e);
    }

    // 发送完整翻译到回调消息所在的聊天（支持分段）
    const { texts, markup } = formatFullTextMessages(article, chatInfo);
    log(`📤 发送翻译全文到 chatId=${chatId}, 分段数=${texts.length}`);
    const lastMsgId = await sendMultipleToChat(config.telegram.botToken, chatId, texts, markup);
    log(`📤 翻译全文发送完成, lastMsgId=${lastMsgId}`);
    article.fullTextMsgId = lastMsgId;
    saveJSON(ARTICLES_FILE, articles);
    
  } else if (data.startsWith("back_")) {
    // 返回摘要 - 直接应答提示用户向上滑动
    // 注意：由于按钮已改为 url 类型，这个分支理论上不会被触发
    // 保留作为兜底处理
    const msgId = parseInt(data.replace("back_", ""));
    log(`↩️ 返回摘要请求（兜底）: msgId=${msgId}, chatId=${chatId}`);
    
    await fetch(
      `https://api.telegram.org/bot${config.telegram.botToken}/answerCallbackQuery`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          callback_query_id: callbackQuery.id,
          text: "↩️ 请向上滑动查找摘要消息",
          show_alert: false,
        }),
      }
    );
    return;

  } else {
    // 未知回调，应答避免 Telegram 显示"无效操作"
    await fetch(
      `https://api.telegram.org/bot${config.telegram.botToken}/answerCallbackQuery`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          callback_query_id: callbackQuery.id,
          text: "⚠️ 未知操作",
        }),
      }
    );
  }
}

// ============ 定时任务 ============
let scheduleTimer: Timer | null = null;

function setupSchedule(config: Config) {
  if (scheduleTimer) {
    clearInterval(scheduleTimer);
    scheduleTimer = null;
  }

  if (!config.schedule.enabled) return;

  // 简单实现：每分钟检查是否匹配 cron
  scheduleTimer = setInterval(() => {
    const now = new Date();
    const [minute, hour] = config.schedule.cron.split(" ");
    
    if (
      (minute === "*" || parseInt(minute) === now.getMinutes()) &&
      (hour === "*" || parseInt(hour) === now.getHours())
    ) {
      log("⏰ 定时任务触发");
      runDigest();
    }
  }, 60000);
}

// ============ 读取外部HTML文件 ============
function readHtmlFile(filename: string): string {
  const filepath = join(import.meta.dir, filename);
  if (existsSync(filepath)) {
    return readFileSync(filepath, "utf-8");
  }
  return `<h1>Error</h1><p>${filename} not found</p>`;
}

// 前端页面: admin.html 为外部文件, 登录页内嵌

// 登录页 HTML (内嵌)
const LOGIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AI Daily - 登录</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f0f0f 0%, #1a1a2e 100%);
      color: #e0e0e0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .login-container {
      background: #1a1a1a;
      border: 1px solid #333;
      border-radius: 12px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    .login-header {
      text-align: center;
      margin-bottom: 30px;
    }
    .login-header h1 {
      font-size: 2rem;
      color: #4f9eff;
      margin-bottom: 8px;
    }
    .login-header p {
      color: #999;
      font-size: 0.9rem;
    }
    .form-group {
      margin-bottom: 20px;
    }
    .form-group label {
      display: block;
      margin-bottom: 8px;
      color: #999;
      font-size: 0.9rem;
    }
    .form-group input {
      width: 100%;
      padding: 12px 16px;
      background: #252525;
      border: 1px solid #333;
      border-radius: 8px;
      color: #e0e0e0;
      font-size: 1rem;
      transition: border-color 0.2s;
    }
    .form-group input:focus {
      outline: none;
      border-color: #4f9eff;
    }
    .btn {
      width: 100%;
      padding: 14px;
      background: #4f9eff;
      border: none;
      border-radius: 8px;
      color: #fff;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    .btn:hover { background: #3a8aee; }
    .btn:disabled { background: #333; cursor: not-allowed; }
    .error-msg {
      background: rgba(244,67,54,0.1);
      border: 1px solid #f44336;
      color: #f44336;
      padding: 12px;
      border-radius: 8px;
      margin-bottom: 20px;
      display: none;
      font-size: 0.9rem;
    }
    .error-msg.show { display: block; }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-header">
      <h1>📰 AI Daily</h1>
      <p>管理后台登录</p>
    </div>
    <div class="error-msg" id="error"></div>
    <form id="loginForm">
      <div class="form-group">
        <label>用户名</label>
        <input type="text" id="username" placeholder="请输入用户名" required>
      </div>
      <div class="form-group">
        <label>密码</label>
        <input type="password" id="password" placeholder="请输入密码" required>
      </div>
      <button type="submit" class="btn" id="submitBtn">登 录</button>
    </form>
  </div>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('submitBtn');
      const error = document.getElementById('error');
      
      btn.disabled = true;
      btn.textContent = '登录中...';
      error.classList.remove('show');
      
      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value,
          }),
        });
        const data = await res.json();
        
        if (data.success) {
          document.cookie = 'token=' + data.token + '; path=/; max-age=86400';
          window.location.href = '/admin';
        } else {
          error.textContent = data.message || '登录失败';
          error.classList.add('show');
        }
      } catch (err) {
        error.textContent = '网络错误，请重试';
        error.classList.add('show');
      }
      
      btn.disabled = false;
      btn.textContent = '登 录';
    });
  </script>
</body>
</html>`;

// ============ HTTP 服务器 ============
const config = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
setupSchedule(config);

// 启动时清理过期数据
cleanupSeenData();
cleanupArticles();

// 每天定时清理一次（使用日期标记避免重复/遗漏）
let lastCleanupDate = "";
setInterval(() => {
  const now = new Date();
  const today = now.toISOString().split("T")[0];
  // 凌晨3-4点之间，且今天还没清理过
  if (now.getHours() === 3 && lastCleanupDate !== today) {
    lastCleanupDate = today;
    log("🧹 执行每日数据清理...");
    cleanupSeenData();
    cleanupArticles();
  }
}, 60000);

serve({
  port: 25333,
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;

    // CORS
    const headers = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (req.method === "OPTIONS") {
      return new Response(null, { headers });
    }

    // 登录页面
    if (path === "/login") {
      return new Response(LOGIN_HTML, {
        headers: { ...headers, "Content-Type": "text/html; charset=utf-8" },
      });
    }

    // 登录 API
    if (path === "/api/login" && req.method === "POST") {
      try {
        const body = await req.json();
        const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
        
        if (body.username === cfg.admin.username && body.password === cfg.admin.password) {
          const token = generateToken(body.username);
          log(`👤 用户登录成功: ${body.username}`);
          return Response.json({ success: true, token }, { headers });
        } else {
          logWarn(`👤 登录失败 (用户名: ${body.username})`);
          return Response.json({ success: false, message: "用户名或密码错误" }, { headers });
        }
      } catch (e) {
        return Response.json({ success: false, message: "请求格式错误" }, { status: 400, headers });
      }
    }

    // 登出 API
    if (path === "/api/logout" && req.method === "POST") {
      return Response.json({ success: true }, {
        headers: {
          ...headers,
          "Set-Cookie": "token=; path=/; max-age=0",
        },
      });
    }

    // 检查认证状态 API
    if (path === "/api/auth/check") {
      const authenticated = isAuthenticated(req);
      return Response.json({ authenticated }, { headers });
    }

    // 根路径重定向到管理后台
    if (path === "/" || path === "/index.html") {
      return new Response(null, {
        status: 302,
        headers: { ...headers, "Location": "/admin" },
      });
    }

    // API: 状态
    if (path === "/api/status") {
      const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
      return Response.json({
        configured: !!cfg.llm.apiKey,
        telegramEnabled: cfg.telegram.enabled,
        scheduleEnabled: cfg.schedule.enabled,
      }, { headers });
    }

    // API: 配置（需要认证）
    if (path === "/api/config") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      if (req.method === "GET") {
        const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
        // 生成 API Key 提示（显示前4位和后4位）
        const maskKey = (key: string) => {
          if (!key || key.length < 12) return key ? "已配置" : "";
          return key.slice(0, 6) + "***" + key.slice(-4);
        };
        // 隐藏敏感信息，但提供提示
        return Response.json({
          ...cfg,
          llm: { ...cfg.llm, apiKey: "", apiKeyHint: maskKey(cfg.llm.apiKey) },
          llmBackup: cfg.llmBackup ? { ...cfg.llmBackup, apiKey: "", apiKeyHint: maskKey(cfg.llmBackup.apiKey) } : { baseUrl: "", apiKey: "", model: "", apiKeyHint: "" },
          llmSettings: cfg.llmSettings || DEFAULT_CONFIG.llmSettings,
          telegram: { ...cfg.telegram, botToken: cfg.telegram.botToken ? "***" : "" },
        }, { headers });
      }

      if (req.method === "POST") {
        const body = await req.json();
        const current = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
        
        // 合并配置，空字符串不覆盖已有值
        const newConfig: Config = {
          llm: {
            baseUrl: body.llm?.baseUrl || current.llm.baseUrl,
            apiKey: (body.llm?.apiKey === "***" || body.llm?.apiKey === "") ? current.llm.apiKey : (body.llm?.apiKey || current.llm.apiKey),
            model: body.llm?.model || current.llm.model,
          },
          llmBackup: {
            baseUrl: body.llmBackup?.baseUrl ?? current.llmBackup?.baseUrl ?? "",
            apiKey: (body.llmBackup?.apiKey === "***" || body.llmBackup?.apiKey === "") ? (current.llmBackup?.apiKey || "") : (body.llmBackup?.apiKey ?? current.llmBackup?.apiKey ?? ""),
            model: body.llmBackup?.model ?? current.llmBackup?.model ?? "",
          },
          llmSettings: {
            timeout: body.llmSettings?.timeout ?? current.llmSettings?.timeout ?? 60000,
            maxRetries: body.llmSettings?.maxRetries ?? current.llmSettings?.maxRetries ?? 2,
            useBackupOnFail: body.llmSettings?.useBackupOnFail ?? current.llmSettings?.useBackupOnFail ?? true,
          },
          rss: { ...current.rss, ...body.rss },
          telegram: {
            ...current.telegram,
            ...body.telegram,
            botToken: body.telegram?.botToken === "***" ? current.telegram.botToken : (body.telegram?.botToken || current.telegram.botToken),
          },
          schedule: { ...current.schedule, ...body.schedule },
          admin: current.admin, // 保留admin配置
        };

        saveJSON(CONFIG_FILE, newConfig);
        setupSchedule(newConfig);
        log("⚙️ 配置已更新");
        return Response.json({ success: true }, { headers });
      }
    }

    // API: 手动运行（需要认证）
    if (path === "/api/run" && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      log("▶️ 手动触发运行任务");
      const result = await runDigest();
      return Response.json(result, { headers });
    }

    // API: 历史
    if (path === "/api/history") {
      const history = loadJSON<any[]>(HISTORY_FILE, []);
      return Response.json(history, { headers });
    }

    // API: 日志（需要认证）
    if (path === "/api/logs") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      
      // 支持查询参数：limit（默认100），level（可选）
      const urlObj = new URL(req.url);
      const limit = Math.min(parseInt(urlObj.searchParams.get("limit") || "100"), MAX_LOGS);
      const level = urlObj.searchParams.get("level");
      
      let logs = logsCache;
      if (level) {
        logs = logs.filter(l => l.level === level);
      }
      
      // 返回最新的日志（倒序）
      return Response.json(logs.slice(-limit).reverse(), { headers });
    }

    // API: 清空日志（需要认证）
    if (path === "/api/logs/clear" && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      logsCache = [];
      writeFileSync(LOG_FILE, "[]");
      return Response.json({ success: true }, { headers });
    }

    // API: 文章详情
    if (path.startsWith("/api/article/")) {
      const id = path.replace("/api/article/", "");
      const articles = loadJSON<Record<string, Article>>(ARTICLES_FILE, {});
      const article = articles[id];
      if (article) {
        return Response.json(article, { headers });
      }
      return Response.json({ error: "Not found" }, { status: 404, headers });
    }

    // API: 翻译（支持 ?force=true 强制重新翻译）
    if (path.startsWith("/api/translate/") && req.method === "POST") {
      const id = path.replace("/api/translate/", "").split("?")[0];
      const forceRetranslate = url.searchParams.get("force") === "true";
      const articles = loadJSON<Record<string, Article>>(ARTICLES_FILE, {});
      const article = articles[id];
      const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);

      if (!article) {
        return Response.json({ error: "Not found" }, { status: 404, headers });
      }

      if (!article.translatedContent || forceRetranslate) {
        log(`📖 ${forceRetranslate ? "强制重新" : ""}翻译文章: ${article.titleZh}`);
        
        // 检查本地内容是否足够，不足则从网页抓取
        let contentToTranslate = article.content;
        const cleanedLocal = cleanContentForTranslation(contentToTranslate);
        
        if (cleanedLocal.length < 500) {
          log(`📄 本地内容太短(${cleanedLocal.length}字符)，从原文链接抓取...`);
          const fetchedContent = await fetchArticleContent(article.link);
          if (fetchedContent.length > cleanedLocal.length) {
            contentToTranslate = fetchedContent;
            article.content = fetchedContent;
            log(`📄 抓取成功，内容长度: ${fetchedContent.length}`);
          }
        }
        
        article.translatedContent = await translateFullText(cfg, contentToTranslate);
        saveJSON(ARTICLES_FILE, articles);
      }

      return Response.json({ content: article.translatedContent }, { headers });
    }

    // API: 清除文章翻译缓存
    if (path.startsWith("/api/article/") && path.endsWith("/clear-translation") && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      const id = path.replace("/api/article/", "").replace("/clear-translation", "");
      const articles = loadJSON<Record<string, Article>>(ARTICLES_FILE, {});
      const article = articles[id];

      if (!article) {
        return Response.json({ error: "Not found" }, { status: 404, headers });
      }

      article.translatedContent = null;
      article.content = "";  // 同时清空本地内容，强制重新抓取
      saveJSON(ARTICLES_FILE, articles);
      log(`🗑️ 已清除文章翻译缓存: ${article.titleZh}`);

      return Response.json({ success: true, message: "翻译缓存已清除" }, { headers });
    }

    // API: 清除所有翻译缓存
    if (path === "/api/articles/clear-all-translations" && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      const articles = loadJSON<Record<string, Article>>(ARTICLES_FILE, {});
      let count = 0;
      for (const id in articles) {
        if (articles[id].translatedContent) {
          articles[id].translatedContent = null;
          articles[id].content = "";  // 强制下次重新抓取
          count++;
        }
      }
      saveJSON(ARTICLES_FILE, articles);
      log(`🗑️ 已清除所有翻译缓存，共 ${count} 篇`);

      return Response.json({ success: true, message: `已清除 ${count} 篇文章的翻译缓存` }, { headers });
    }

    // Telegram Webhook
    if (path === "/webhook/telegram" && req.method === "POST") {
      const body = await req.json();
      if (body.callback_query) {
        handleTelegramCallback(body.callback_query);
      }
      return Response.json({ ok: true }, { headers });
    }

    // API: 测试 Telegram 推送（需要认证）
    if (path === "/api/telegram/test" && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      
      const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
      
      if (!cfg.telegram.botToken || !cfg.telegram.chatId) {
        return Response.json({ 
          success: false, 
          message: "请先配置 Bot Token 和 Chat ID" 
        }, { headers });
      }
      
      // 发送测试消息
      const testMessage = `┏━━━━━━━━━━━━━━━━━━━━┓
┃ 🧪 <b>测试消息</b>
┗━━━━━━━━━━━━━━━━━━━━┛

<b>📌 AI Daily Digest 测试</b>
<i>This is a test message</i>

━━━ 📝 摘要 ━━━
这是一条测试消息，用于验证 Telegram 推送功能是否正常工作。

━━━ 💡 推荐理由 ━━━
配置验证测试

🏷️ <code>测试 · Telegram · AI Daily</code>

⏰ 发送时间: ${new Date().toLocaleString('zh-CN')}`;

      try {
        const res = await fetch(
          `https://api.telegram.org/bot${cfg.telegram.botToken}/sendMessage`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              chat_id: cfg.telegram.chatId,
              text: testMessage,
              parse_mode: "HTML",
            }),
          }
        );
        
        const data = await res.json();
        
        if (data.ok) {
          return Response.json({ success: true, message: "测试消息已发送" }, { headers });
        } else {
          return Response.json({ 
            success: false, 
            message: data.description || "发送失败" 
          }, { headers });
        }
      } catch (e: any) {
        return Response.json({ 
          success: false, 
          message: e.message || "网络错误" 
        }, { headers });
      }
    }

    // API: 设置 Telegram Webhook（需要认证）
    if (path === "/api/telegram/webhook" && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }

      try {
        const body = await req.json();
        const { webhookUrl } = body;
        const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);

        if (!cfg.telegram.botToken) {
          return Response.json({ success: false, message: "请先配置 Bot Token" }, { headers });
        }

        // 如果提供了 URL，设置 webhook；否则删除 webhook
        const telegramUrl = webhookUrl
          ? `https://api.telegram.org/bot${cfg.telegram.botToken}/setWebhook`
          : `https://api.telegram.org/bot${cfg.telegram.botToken}/deleteWebhook`;
        
        const res = await fetch(telegramUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(webhookUrl ? { url: webhookUrl } : {}),
        });
        
        const data = await res.json();
        
        if (data.ok) {
          log(webhookUrl ? `🔗 Webhook 设置成功: ${webhookUrl}` : "🔗 Webhook 已删除");
          return Response.json({ 
            success: true, 
            message: webhookUrl ? "Webhook 设置成功" : "Webhook 已删除"
          }, { headers });
        } else {
          logError(`Webhook 设置失败: ${data.description || "未知错误"}`);
          return Response.json({ 
            success: false, 
            message: data.description || "设置失败" 
          }, { headers });
        }
      } catch (e: any) {
        logError(`Webhook 设置异常: ${e.message}`);
        return Response.json({ success: false, message: e.message }, { headers });
      }
    }

    // API: 获取 Telegram Webhook 状态（需要认证）
    if (path === "/api/telegram/webhook" && req.method === "GET") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }

      try {
        const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);

        if (!cfg.telegram.botToken) {
          return Response.json({ success: false, message: "请先配置 Bot Token" }, { headers });
        }

        const res = await fetch(
          `https://api.telegram.org/bot${cfg.telegram.botToken}/getWebhookInfo`
        );
        const data = await res.json();
        
        if (data.ok) {
          return Response.json({ 
            success: true, 
            url: data.result.url || "",
            pendingUpdateCount: data.result.pending_update_count || 0,
            lastErrorMessage: data.result.last_error_message || "",
          }, { headers });
        } else {
          return Response.json({ success: false, message: "获取失败" }, { headers });
        }
      } catch (e: any) {
        return Response.json({ success: false, message: e.message }, { headers });
      }
    }

    // API: 获取 LLM 模型列表（需要认证）
    if (path === "/api/llm/models" && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      try {
        const body = await req.json().catch(() => ({}));
        let baseUrl = body.baseUrl;
        let apiKey = body.apiKey;
        const type = body.type; // 'primary' 或 'backup'
        
        // 如果请求体没有提供，从配置读取（根据 type 决定读取哪个配置）
        if (!baseUrl || !apiKey) {
          const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
          const isBackup = type === 'backup';
          const savedConfig = isBackup ? cfg.llmBackup : cfg.llm;
          baseUrl = baseUrl || savedConfig?.baseUrl;
          apiKey = apiKey || savedConfig?.apiKey;
        }
        
        if (!baseUrl || !apiKey) {
          return Response.json({ error: "请先配置 API Base URL 和 API Key" }, { status: 400, headers });
        }
        
        const res = await fetch(`${baseUrl}/models`, {
          headers: { Authorization: `Bearer ${apiKey}` },
        });
        if (!res.ok) {
          return Response.json({ error: `API 请求失败: ${res.status}` }, { status: res.status, headers });
        }
        const data = await res.json();
        const models = (data.data || []).map((m: any) => m.id).sort();
        return Response.json({ models }, { headers });
      } catch (e: any) {
        return Response.json({ error: e.message || "获取模型列表失败" }, { status: 500, headers });
      }
    }

    // API: 单独测试 LLM 连接（需要认证）
    if (path === "/api/llm/test-single" && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }

      try {
        const body = await req.json();
        let { baseUrl, apiKey, model, type } = body;
        
        // 如果没有提供，从已保存的配置读取
        if (!baseUrl || !apiKey) {
          const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
          const isBackup = type === 'backup';
          const savedConfig = isBackup ? cfg.llmBackup : cfg.llm;
          baseUrl = baseUrl || savedConfig?.baseUrl;
          apiKey = apiKey || savedConfig?.apiKey;
          model = model || savedConfig?.model;
        }
        
        if (!baseUrl || !apiKey) {
          return Response.json({ error: "请先配置 API Base URL 和 API Key" }, { status: 400, headers });
        }

        const testPrompt = "Hi, please respond with 'OK' to confirm the connection is working.";
        const llmConfig: LLMConfig = { baseUrl, apiKey, model: model || "gpt-3.5-turbo" };
        
        const result = await callLLMOnce(llmConfig, testPrompt, 15000);
        return Response.json({ success: !!result }, { headers });
      } catch (e: any) {
        return Response.json({ success: false, error: e.message }, { headers });
      }
    }

    // API: 测试所有 LLM 连接（需要认证）
    if (path === "/api/llm/test" && req.method === "POST") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }

      const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
      const testPrompt = "Hi, please respond with 'OK' to confirm the connection is working.";
      
      let primarySuccess = false;
      let primaryError = "";
      let backupTested = false;
      let backupSuccess = false;
      let backupError = "";
      
      // 测试主 LLM
      if (cfg.llm.apiKey) {
        try {
          const result = await callLLMOnce(cfg.llm, testPrompt, 15000);
          primarySuccess = !!result;
        } catch (e: any) {
          primaryError = e.message;
        }
      } else {
        primaryError = "未配置主 LLM";
      }
      
      // 测试备用 LLM
      if (cfg.llmBackup?.apiKey) {
        backupTested = true;
        try {
          const result = await callLLMOnce(cfg.llmBackup, testPrompt, 15000);
          backupSuccess = !!result;
        } catch (e: any) {
          backupError = e.message;
        }
      }
      
      return Response.json({
        success: primarySuccess,
        message: primarySuccess ? "主 LLM 连接成功" : primaryError,
        backupTested,
        backupSuccess,
        backupError: backupError || undefined,
      }, { headers });
    }

    // API: RSS 源管理（需要认证）
    if (path === "/api/rss") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      if (req.method === "GET") {
        const feeds = getRSSFeeds();
        return Response.json(feeds, { headers });
      }
      if (req.method === "POST") {
        const body = await req.json();
        if (Array.isArray(body)) {
          saveJSON(RSS_FILE, body);
          log(`📡 RSS 源已更新 (共 ${body.length} 个)`);
          return Response.json({ success: true }, { headers });
        }
        return Response.json({ error: "Invalid format" }, { status: 400, headers });
      }
    }

    // API: 账号管理（需要认证）
    if (path === "/api/admin/account") {
      if (!isAuthenticated(req)) {
        return Response.json({ error: "未授权访问" }, { status: 401, headers });
      }
      
      const cfg = loadJSON<Config>(CONFIG_FILE, DEFAULT_CONFIG);
      
      if (req.method === "GET") {
        // 返回当前用户名（不返回密码）
        return Response.json({ username: cfg.admin?.username || "admin" }, { headers });
      }
      
      if (req.method === "POST") {
        try {
          const body = await req.json();
          const { username, currentPassword, newPassword } = body;
          
          // 验证当前密码
          if (currentPassword !== cfg.admin?.password) {
            return Response.json({ success: false, message: "当前密码错误" }, { headers });
          }
          
          // 验证新用户名
          if (!username || username.trim().length < 2) {
            return Response.json({ success: false, message: "用户名至少2个字符" }, { headers });
          }
          
          // 更新配置
          const updatedConfig = {
            ...cfg,
            admin: {
              username: username.trim(),
              password: newPassword || cfg.admin.password, // 如果没有新密码则保持原密码
            },
          };
          
          saveJSON(CONFIG_FILE, updatedConfig);
          log(`🔐 账号信息已更新: ${username.trim()}`);
          
          return Response.json({ success: true, message: "账号信息已更新" }, { headers });
        } catch (e: any) {
          logError(`账号更新失败: ${e.message}`);
          return Response.json({ success: false, message: e.message || "更新失败" }, { status: 400, headers });
        }
      }
    }

    // 管理后台页面（需要认证）
    if (path === "/admin") {
      if (!isAuthenticated(req)) {
        // 未登录，重定向到登录页
        return new Response(null, {
          status: 302,
          headers: { ...headers, "Location": "/login" },
        });
      }
      const html = readHtmlFile("admin.html");
      return new Response(html, {
        headers: { ...headers, "Content-Type": "text/html; charset=utf-8" },
      });
    }

    return new Response("Not Found", { status: 404, headers });
  },
});

log("🚀 AI Daily 运行在 http://localhost:25333");
