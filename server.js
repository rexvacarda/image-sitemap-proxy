import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import { URL } from "url";

const app = express();

/* ========= CONFIG via ENV (HYBRID: App Proxy + Custom App Token) =========
Required:
  SHOP                -> your admin domain, e.g. smelltoimpress.myshopify.com  (from App B store)
  ADMIN_API_TOKEN     -> Admin API access token from your Custom App (App B)
  SHARED_SECRET       -> App Proxy "Shared secret" from Partner App (App A)

Optional:
  API_VERSION         -> default 2024-04
  CACHE_TTL_SECONDS   -> default 900 (15m)
  MAX_URLS_PER_FEED   -> default 5000 (keep < 50k)
  DEFAULT_PER_PAGE    -> default 200 (safe for proxy timeouts)
  HTTP_TIMEOUT_MS     -> default 12000
  TRANS_CONCURRENCY   -> default 8 (translation fetch concurrency)
======================================================================== */

const SHOP = process.env.SHOP || "";                  // e.g. smelltoimpress.myshopify.com
const ADMIN_API_TOKEN = process.env.ADMIN_API_TOKEN || "";
const SHARED_SECRET = process.env.SHARED_SECRET || "";

const API_VERSION = process.env.API_VERSION || "2024-04";
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 900);
const MAX_URLS_PER_FEED = Number(process.env.MAX_URLS_PER_FEED || 5000);
const DEFAULT_PER_PAGE = Math.min(Number(process.env.DEFAULT_PER_PAGE || 200), MAX_URLS_PER_FEED);
const HTTP_TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 12000);
const TRANS_CONCURRENCY = Math.max(1, Number(process.env.TRANS_CONCURRENCY || 8));

// quick sanity logs (won't print secrets)
if (!SHOP) console.error("[startup] Missing SHOP env");
if (!ADMIN_API_TOKEN) console.error("[startup] Missing ADMIN_API_TOKEN env");
if (!SHARED_SECRET) console.error("[startup] Missing SHARED_SECRET env");

// Simple in-memory response cache
const responseCache = new Map(); // key => { body, expiresAt }

/* ======================== Utilities ======================== */

function cacheKey(parts) {
  return Object.entries(parts).map(([k,v]) => `${k}=${v}`).sort().join("|");
}

function setXmlHeaders(res) {
  res.set("Content-Type", "application/xml; charset=utf-8");
  res.set("Cache-Control", `public, max-age=${CACHE_TTL_SECONDS}`);
}

function x(s = "") {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function stripPort(host) {
  return (host || "").replace(/:.+$/, "");
}

function preferHostImageUrl(originalUrl, host) {
  try {
    const u = new URL(originalUrl);
    if (u.hostname !== "cdn.shopify.com") return originalUrl;
    const path = u.pathname; // /s/files/.../(products|files)/...
    const idxProducts = path.indexOf("/products/");
    const idxFiles = path.indexOf("/files/");
    let rebuilt = null;
    if (idxProducts !== -1) rebuilt = `/cdn/shop${path.substring(idxProducts)}${u.search || ""}`;
    else if (idxFiles !== -1) rebuilt = `/cdn/shop${path.substring(idxFiles)}${u.search || ""}`;
    return rebuilt ? `https://${host}${rebuilt}` : originalUrl;
  } catch {
    return originalUrl;
  }
}

function pageUrlForProduct(host, handle, onlineStoreUrl) {
  const h = stripPort(host);
  if (onlineStoreUrl) return onlineStoreUrl.replace(/^https?:\/\/[^/]+/, `https://${h}`);
  return `https://${h}/products/${handle}`;
}

function pageUrlForCollection(host, handle) {
  const h = stripPort(host);
  return `https://${h}/collections/${handle}`;
}

// Verify Shopify App Proxy signature (from App A)
function verifyProxyHmac(req) {
  const { signature, ...params } = req.query;
  if (!SHARED_SECRET || !signature) return false;
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join("");
  const digest = crypto.createHmac("sha256", SHARED_SECRET).update(sorted).digest("hex");
  return signature === digest;
}

// locale mapping by host (override via ?locale=)
function getLocaleForHost(host, override) {
  if (override) return override.toLowerCase();
  const h = (host || "").toLowerCase();
  if (h.endsWith(".fr")) return "fr";
  if (h.endsWith(".it")) return "it";
  if (h.startsWith("ko.")) return "ko";
  if (h.startsWith("ar.")) return "ar";
  if (h.startsWith("iw.")) return "he"; // Shopify uses 'he'
  if (h.endsWith(".nl")) return "nl";
  if (h.endsWith(".ch")) return "de";
  return "en";
}

// Extract numeric ID from gid://shopify/Thing/1234567890
function numericIdFromGid(gid) {
  if (!gid) return null;
  const parts = String(gid).split("/");
  return parts.length ? parts[parts.length - 1] : null;
}

// timed fetch
async function timedFetch(url, opts = {}, timeoutMs = HTTP_TIMEOUT_MS) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...opts, signal: controller.signal });
    return resp;
  } finally {
    clearTimeout(t);
  }
}

// concurrency limiter
async function pMap(items, limit, mapper) {
  const ret = [];
  const executing = [];
  for (const item of items) {
    const p = Promise.resolve().then(() => mapper(item));
    ret.push(p);
    if (limit <= items.length) {
      const e = p.then(() => executing.splice(executing.indexOf(e), 1));
      executing.push(e);
      if (executing.length >= limit) {
        await Promise.race(executing);
      }
    }
  }
  return Promise.all(ret);
}

/* ================= Shopify Admin fetchers ================= */

// GraphQL paged fetcher helper: returns a slice (offset/take) without pulling everything
async function gqlPagedSlice({ query, selectEdges, first, offset, take }) {
  let after = null;
  let skipped = 0;
  const out = [];
  while (out.length < take) {
    const resp = await timedFetch(`https://${SHOP}/admin/api/${API_VERSION}/graphql.json`, {
      method: "POST",
      headers: {
        "X-Shopify-Access-Token": ADMIN_API_TOKEN,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ query, variables: { first, after } }),
    });
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Admin API ${resp.status}: ${text}`);
    }
    const json = await resp.json();
    const edges = selectEdges(json) || [];
    if (!edges.length) break;

    for (const e of edges) {
      if (skipped < offset) {
        skipped += 1;
      } else if (out.length < take) {
        out.push(e.node);
      } else {
        break;
      }
    }
    const pageInfo = edges?.length
      ? json.data[Object.keys(json.data)[0]].pageInfo
      : { hasNextPage: false };

    if (!pageInfo?.hasNextPage || out.length >= take) break;
    after = edges[edges.length - 1].cursor;
  }
  return out;
}

async function getProductsSlice(offset, limit) {
  const query = `
    query Products($first:Int!, $after:String) {
      products(first:$first, after:$after, query:"status:active", sortKey:UPDATED_AT, reverse:true) {
        edges {
          cursor
          node {
            id
            title
            handle
            onlineStoreUrl
            updatedAt
            images(first:50) {
              edges { node { id url altText } }
            }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  `;
  return gqlPagedSlice({
    query,
    selectEdges: (j) => j?.data?.products?.edges,
    first: 100,
    offset,
    take: limit,
  });
}

async function getCollectionsSlice(offset, limit) {
  const query = `
    query Collections($first:Int!, $after:String) {
      collections(first:$first, after:$after, query:"published_status:published", sortKey:UPDATED_AT, reverse:true) {
        edges {
          cursor
          node {
            id
            title
            handle
            updatedAt
            image { id url altText }
          }
        }
        pageInfo { hasNextPage }
      }
    }
  `;
  return gqlPagedSlice({
    query,
    selectEdges: (j) => j?.data?.collections?.edges,
    first: 200,
    offset,
    take: limit,
  });
}

/* ===== Translations via Admin REST (needs read_translations) ===== */

async function fetchProductTranslations(numericId, locale) {
  const url = `https://${SHOP}/admin/api/${API_VERSION}/translations.json?locale=${encodeURIComponent(locale)}&resource_type=Product&resource_id=${numericId}`;
  const resp = await timedFetch(url, {
    headers: { "X-Shopify-Access-Token": ADMIN_API_TOKEN, "Content-Type": "application/json" }
  });
  if (!resp.ok) return null;
  const json = await resp.json();
  return json?.translations || null;
}

async function fetchCollectionTranslations(numericId, locale) {
  const url = `https://${SHOP}/admin/api/${API_VERSION}/translations.json?locale=${encodeURIComponent(locale)}&resource_type=Collection&resource_id=${numericId}`;
  const resp = await timedFetch(url, {
    headers: { "X-Shopify-Access-Token": ADMIN_API_TOKEN, "Content-Type": "application/json" }
  });
  if (!resp.ok) return null;
  const json = await resp.json();
  return json?.translations || null;
}

/* ===== Helpers for translated fallbacks ===== */

function extractTranslatedValue(translations, keyExact) {
  if (!translations) return "";
  for (const t of translations) {
    if (t.key === keyExact && t.value) return String(t.value);
  }
  return "";
}

function buildImageAltMapFromTranslations(translations) {
  const map = new Map(); // "*" or "<numericImageId>" -> altText
  if (!translations) return map;
  for (const t of translations) {
    if (!t?.key || !t?.value) continue;
    if (t.key === "image.alt_text") {
      map.set("*", String(t.value));
      continue;
    }
    const m = t.key.match(/^image\[(\d+)\]\.alt$/i);
    if (m) map.set(m[1], String(t.value));
  }
  return map;
}

/* ================= XML builders ================= */

function buildImageNode(loc, title, caption) {
  return `
        <image:image>
          <image:loc>${x(loc)}</image:loc>
          ${title ? `<image:title>${x(title)}</image:title>` : ""}
          ${caption ? `<image:caption>${x(caption)}</image:caption>` : ""}
        </image:image>`;
}

function buildUrlNode(pageLoc, lastmodISO, imageNodes) {
  return `<url>
      <loc>${x(pageLoc)}</loc>
      ${lastmodISO ? `<lastmod>${x(lastmodISO)}</lastmod>` : ""}${imageNodes.join("")}
    </url>`;
}

/* ================= Main endpoints (App Proxy) ================= */

// Image sitemap (products | collections | all)
app.get("/image.xml", async (req, res) => {
  try {
    if (!verifyProxyHmac(req)) return res.status(401).send("Invalid signature");

    const forwardedHost = req.get("x-forwarded-host") || req.get("host");
    const host = stripPort(forwardedHost);

    const page = Math.max(parseInt(req.query.page || "1", 10), 1);
    const perPageRaw = Math.max(parseInt(req.query.per_page || String(DEFAULT_PER_PAGE), 10), 1);
    const perPage = Math.min(perPageRaw, MAX_URLS_PER_FEED);
    const type = (req.query.type || "all").toLowerCase(); // products|collections|all
    const includeCaptions = String(req.query.captions || "1") === "1";
    const preferHost = String(req.query.prefer_host || "1") === "1";
    const locale = getLocaleForHost(host, req.query.locale);
    const debug = String(req.query.debug || "0") === "1";

    // cache
    const key = cacheKey({ route: "image.xml", host, page, perPage, type, includeCaptions, preferHost, locale });
    const hit = responseCache.get(key);
    const now = Date.now();
    if (hit && hit.expiresAt > now) {
      setXmlHeaders(res);
      return res.status(200).send(hit.body);
    }

    const offset = (page - 1) * perPage;
    const nodes = [];

    // --- PRODUCTS ---
    if (type === "products" || type === "all") {
      const products = await getProductsSlice(offset, perPage);

      // fetch translations for this slice concurrently
      const prodTrans = await pMap(
        products.map(p => ({ p, idNum: numericIdFromGid(p.id) })),
        TRANS_CONCURRENCY,
        async ({ p, idNum }) => {
          let trs = null;
          if (idNum) trs = await fetchProductTranslations(idNum, locale);
          return { id: p.id, trs };
        }
      );
      const transMap = new Map(prodTrans.map(r => [r.id, r.trs || []]));

      for (const p of products) {
        const pageUrl = pageUrlForProduct(host, p.handle, p.onlineStoreUrl);
        const images = (p.images?.edges || []).map((e) => e.node);
        if (!images.length) continue;

        const trs = transMap.get(p.id) || [];
        const productTitleTr = extractTranslatedValue(trs, "title") || "";
        const imageAltMap = buildImageAltMapFromTranslations(trs);

        const imageNodes = images.map((img) => {
          const imgIdNum = numericIdFromGid(img.id);
          const translatedAlt =
            (imgIdNum && imageAltMap.get(imgIdNum)) ||
            imageAltMap.get("*") ||
            ""; // strict: no EN fallback

          const resolved = translatedAlt || productTitleTr || "";
          const imgUrl = preferHost ? preferHostImageUrl(img.url, host) : img.url;

          const title = resolved ? resolved : "";
          const caption = includeCaptions && resolved ? resolved : "";

          return buildImageNode(imgUrl, title, caption);
        });

        nodes.push(buildUrlNode(pageUrl, p.updatedAt, imageNodes));
      }
    }

    // --- COLLECTIONS ---
    if (type === "collections" || type === "all") {
      const collections = await getCollectionsSlice(offset, perPage);

      const colTrans = await pMap(
        collections.map(c => ({ c, idNum: numericIdFromGid(c.id) })),
        TRANS_CONCURRENCY,
        async ({ c, idNum }) => {
          let trs = null;
          if (idNum) trs = await fetchCollectionTranslations(idNum, locale);
          return { id: c.id, trs };
        }
      );
      const transMap = new Map(colTrans.map(r => [r.id, r.trs || []]));

      for (const c of collections) {
        if (!c.image?.url) continue;
        const pageUrl = pageUrlForCollection(host, c.handle);

        const trs = transMap.get(c.id) || [];
        const collectionTitleTr = extractTranslatedValue(trs, "title") || "";

        // Resolve translated alt for this collection image
        const imgIdNum = numericIdFromGid(c.image?.id);
        let imageAltTr = "";
        for (const t of trs) {
          if (!t?.key || !t?.value) continue;
          if (t.key === "image.alt_text") imageAltTr = String(t.value);
          const m = t.key.match(/^image\[(\d+)\]\.alt$/i);
          if (m && imgIdNum && m[1] === String(imgIdNum)) imageAltTr = String(t.value);
        }

        const resolved = imageAltTr || collectionTitleTr || "";
        const imgUrl = preferHost ? preferHostImageUrl(c.image.url, host) : c.image.url;

        const title = resolved ? resolved : "";
        const caption = includeCaptions && resolved ? resolved : "";
        const imageNodes = [buildImageNode(imgUrl, title, caption)];

        nodes.push(buildUrlNode(pageUrl, c.updatedAt, imageNodes));
      }
    }

    const debugComment = debug
      ? `\n<!-- locale=${locale} host=${host} type=${type} page=${page} per_page=${perPage} -->\n`
      : "";

    const xml = `<?xml version="1.0" encoding="UTF-8"?>${debugComment}
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${nodes.join("\n")}
</urlset>`;

    responseCache.set(key, { body: xml, expiresAt: now + CACHE_TTL_SECONDS * 1000 });
    setXmlHeaders(res);
    return res.status(200).send(xml);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Sitemap generation error");
  }
});

// Simple index helper
app.get("/image-index.xml", (req, res) => {
  const forwardedHost = req.get("x-forwarded-host") || req.get("host");
  const host = stripPort(forwardedHost);
  const pages = Number(req.query.pages || 5);
  const type = String(req.query.type || "products");
  const perPage = Number(req.query.per_page || DEFAULT_PER_PAGE);
  const locale = req.query.locale ? `&locale=${encodeURIComponent(req.query.locale)}` : "";

  const urls = Array.from({ length: pages }, (_, i) => i + 1).map(
    (n) => `<sitemap><loc>https://${host}/apps/sitemaps/image.xml?type=${encodeURIComponent(type)}&page=${n}&per_page=${perPage}${locale}</loc></sitemap>`
  );

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</sitemapindex>`;

  setXmlHeaders(res);
  return res.status(200).send(xml);
});

// Health & root
app.get("/health", (_req, res) => res.type("text/plain").send("ok"));
app.get("/", (_req, res) =>
  res.type("text/plain").send("Image Sitemap Proxy (hybrid) running. Use /health, or call via Shopify App Proxy at /apps/sitemaps/image.xml")
);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Image sitemap proxy (hybrid) on :${port}`));

