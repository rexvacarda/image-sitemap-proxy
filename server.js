import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import { URL } from "url";

const app = express();

/* ========= CONFIG via ENV =========
Required (OAuth app installed per shop):
  APP_API_KEY        -> Client ID (Partner app)
  APP_API_SECRET     -> API secret key (also App Proxy shared secret for HMAC)
  HOST               -> Public base URL, e.g. https://image-sitemap-proxy.onrender.com
  SCOPES             -> e.g. read_products,read_translations

Optional:
  API_VERSION        -> default 2024-04
  CACHE_TTL_SECONDS  -> default 900 (15m)
  MAX_URLS_PER_FEED  -> default 5000 (keep < 50k)
  DEFAULT_PER_PAGE   -> default 200 (safe for proxy timeout)
  HTTP_TIMEOUT_MS    -> default 12000 (12s per upstream call)
  TRANS_CONCURRENCY  -> default 8 (translation fetch concurrency)
=================================== */

const APP_API_KEY = process.env.APP_API_KEY || "";
const APP_API_SECRET = process.env.APP_API_SECRET || "";
const HOST = process.env.HOST || "";
const SCOPES = process.env.SCOPES || "read_products,read_translations";

const API_VERSION = process.env.API_VERSION || "2024-04";
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 900);
const MAX_URLS_PER_FEED = Number(process.env.MAX_URLS_PER_FEED || 5000);
const DEFAULT_PER_PAGE = Math.min(Number(process.env.DEFAULT_PER_PAGE || 200), MAX_URLS_PER_FEED);
const HTTP_TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 12000);
const TRANS_CONCURRENCY = Math.max(1, Number(process.env.TRANS_CONCURRENCY || 8));

// In-memory token store per shop (replace with Redis for production)
const tokenStore = new Map(); // shop => { accessToken, installedAt }

// Simple in-memory response cache
const responseCache = new Map(); // key => { body, expiresAt }

/* ========== Small utils ========== */

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

function verifyProxyHmac(req) {
  const { signature, ...params } = req.query;
  if (!APP_API_SECRET || !signature) return false;
  const sorted = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join("");
  const digest = crypto.createHmac("sha256", APP_API_SECRET).update(sorted).digest("hex");
  return signature === digest;
}

// Map host → Shopify locale code
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

// node-fetch with timeout
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

// Simple concurrency limiter
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

/* ===== NEW helpers for translated fallbacks (points 1 & 2) ===== */
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

/* ========== OAuth (public app) minimal flow ========== */
app.get("/auth", (req, res) => {
  const shop = String(req.query.shop || "");
  if (!shop || !shop.endsWith(".myshopify.com")) {
    return res.status(400).send("Missing/invalid shop");
  }
  const state = crypto.randomBytes(12).toString("hex");
  const redirectUri = `${HOST}/auth/callback`;
  const url = `https://${shop}/admin/oauth/authorize?client_id=${APP_API_KEY}` +
              `&scope=${encodeURIComponent(SCOPES)}` +
              `&redirect_uri=${encodeURIComponent(redirectUri)}` +
              `&state=${state}`;
  res.redirect(url);
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { shop, code } = req.query;
    if (!shop || !code) return res.status(400).send("Missing shop/code");
    const tokenResp = await timedFetch(`https://${shop}/admin/oauth/access_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_id: APP_API_KEY,
        client_secret: APP_API_SECRET,
        code
      })
    });
    if (!tokenResp.ok) {
      const t = await tokenResp.text();
      return res.status(400).send(`Token exchange failed: ${t}`);
    }
    const json = await tokenResp.json();
    tokenStore.set(shop, { accessToken: json.access_token, installedAt: Date.now() });
    res
      .type("text/plain")
      .send(`Installed for ${shop}. Token stored in memory. You can now hit your App Proxy: https://${stripPort(req.get("host"))}/apps/sitemaps/image.xml`);
  } catch (err) {
    console.error(err);
    res.status(500).send("OAuth error");
  }
});

/* ========== Admin API fetchers (cursor-only page slice) ========== */

// GraphQL paged fetcher helper
async function gqlPagedSlice({ shop, token, query, selectEdges, first, offset, take }) {
  let after = null;
  let skipped = 0;
  const out = [];
  while (out.length < take) {
    const resp = await timedFetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
      method: "POST",
      headers: {
        "X-Shopify-Access-Token": token,
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

async function getProductsSlice(shop, token, offset, limit) {
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
    shop,
    token,
    query,
    selectEdges: (j) => j?.data?.products?.edges,
    first: 100,
    offset,
    take: limit,
  });
}

async function getCollectionsSlice(shop, token, offset, limit) {
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
    shop,
    token,
    query,
    selectEdges: (j) => j?.data?.collections?.edges,
    first: 200,
    offset,
    take: limit,
  });
}

/* ========== Admin REST Translations (slice-only, with concurrency cap) ========== */

async function fetchProductTranslations(shop, token, numericId, locale) {
  const url = `https://${shop}/admin/api/${API_VERSION}/translations.json?locale=${encodeURIComponent(locale)}&resource_type=Product&resource_id=${numericId}`;
  const resp = await timedFetch(url, {
    headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" }
  });
  if (!resp.ok) return null;
  const json = await resp.json();
  return json?.translations || null;
}

async function fetchCollectionTranslations(shop, token, numericId, locale) {
  const url = `https://${shop}/admin/api/${API_VERSION}/translations.json?locale=${encodeURIComponent(locale)}&resource_type=Collection&resource_id=${numericId}`;
  const resp = await timedFetch(url, {
    headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" }
  });
  if (!resp.ok) return null;
  const json = await resp.json();
  return json?.translations || null;
}

/* ========== XML builders ========== */

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

/* ========== Main proxy endpoints ========== */
app.get("/image.xml", async (req, res) => {
  try {
    if (!verifyProxyHmac(req)) return res.status(401).send("Invalid signature");

    const forwardedHost = req.get("x-forwarded-host") || req.get("host");
    const host = stripPort(forwardedHost);
    const shop = String(req.query.shop || "");
    const page = Math.max(parseInt(req.query.page || "1", 10), 1);
    const perPageRaw = Math.max(parseInt(req.query.per_page || String(DEFAULT_PER_PAGE), 10), 1);
    const perPage = Math.min(perPageRaw, MAX_URLS_PER_FEED);
    const type = (req.query.type || "all").toLowerCase(); // products|collections|all
    const includeCaptions = String(req.query.captions || "1") === "1";
    const preferHost = String(req.query.prefer_host || "1") === "1";
    const locale = getLocaleForHost(host, req.query.locale);
    const debug = String(req.query.debug || "0") === "1";

    // cache
    const key = cacheKey({ route: "image.xml", host, shop, page, perPage, type, includeCaptions, preferHost, locale });
    const hit = responseCache.get(key);
    const now = Date.now();
    if (hit && hit.expiresAt > now) {
      setXmlHeaders(res);
      return res.status(200).send(hit.body);
    }

    const tokenEntry = tokenStore.get(shop);
    if (!tokenEntry?.accessToken) {
      return res
        .status(403)
        .type("text/plain")
        .send(`App not installed for ${shop}. Visit ${HOST}/auth?shop=${shop}`);
    }
    const accessToken = tokenEntry.accessToken;

    const offset = (page - 1) * perPage;
    const nodes = [];

    // PRODUCTS
    if (type === "products" || type === "all") {
      const products = await getProductsSlice(shop, accessToken, offset, perPage);

      // translations for this slice
      const prodTrans = await pMap(
        products.map(p => ({ p, idNum: numericIdFromGid(p.id) })),
        TRANS_CONCURRENCY,
        async ({ p, idNum }) => {
          let trs = null;
          if (idNum) trs = await fetchProductTranslations(shop, accessToken, idNum, locale);
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
            ""; // no EN fallback

          const resolved = translatedAlt || productTitleTr || "";
          const imgUrl = preferHost ? preferHostImageUrl(img.url, host) : img.url;

          const title = resolved ? resolved : "";
          const caption = includeCaptions && resolved ? resolved : "";

          return buildImageNode(imgUrl, title, caption);
        });

        nodes.push(buildUrlNode(pageUrl, p.updatedAt, imageNodes));
      }
    }

    // COLLECTIONS
    if (type === "collections" || type === "all") {
      const collections = await getCollectionsSlice(shop, accessToken, offset, perPage);

      const colTrans = await pMap(
        collections.map(c => ({ c, idNum: numericIdFromGid(c.id) })),
        TRANS_CONCURRENCY,
        async ({ c, idNum }) => {
          let trs = null;
          if (idNum) trs = await fetchCollectionTranslations(shop, accessToken, idNum, locale);
          return { id: c.id, trs };
        }
      );
      const transMap = new Map(colTrans.map(r => [r.id, r.trs || []]));

      for (const c of collections) {
        if (!c.image?.url) continue;
        const pageUrl = pageUrlForCollection(host, c.handle);

        const trs = transMap.get(c.id) || [];
        const collectionTitleTr = extractTranslatedValue(trs, "title") || "";
        const imgIdNum = numericIdFromGid(c.image?.id);

        // image alt translation (specific image or global)
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

// Sanity check
app.get("/echo", (_req, res) => res.type("text/plain").send("echo ok"));

/* Optional: lightweight index */
app.get("/image-index.xml", (req, res) => {
  const forwardedHost = req.get("x-forwarded-host") || req.get("host");
  const host = stripPort(forwardedHost);
  const shop = String(req.query.shop || "");
  const pages = Number(req.query.pages || 5);
  const type = String(req.query.type || "products");
  const perPage = Number(req.query.per_page || DEFAULT_PER_PAGE);
  const locale = req.query.locale ? `&locale=${encodeURIComponent(req.query.locale)}` : "";

  const urls = Array.from({ length: pages }, (_, i) => i + 1).map(
    (n) => `<sitemap><loc>https://${host}/apps/sitemaps/image.xml?shop=${shop}&type=${encodeURIComponent(type)}&page=${n}&per_page=${perPage}${locale}</loc></sitemap>`
  );

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</sitemapindex>`;

  setXmlHeaders(res);
  return res.status(200).send(xml);
});

/* Health & root */
app.get("/health", (_req, res) => res.type("text/plain").send("ok"));
app.get("/", (_req, res) => {
  res
    .type("text/plain")
    .send("Image Sitemap Proxy is running. Use /health, /echo, or call via Shopify App Proxy at /apps/sitemaps/image.xml");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Image sitemap proxy on :${port}`));
