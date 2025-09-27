import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import { URL } from "url";

const app = express();

/* ========= CONFIG via ENV =========
Required (OAuth app installed per shop):
  APP_API_KEY        -> Client ID from Partner app (used by OAuth routes)
  APP_API_SECRET     -> API secret key (also App Proxy shared secret for HMAC)
  HOST               -> Public base URL of this server, e.g. https://image-sitemap-proxy.onrender.com
  SCOPES             -> e.g. read_products,read_translations

Optional:
  API_VERSION        -> Admin API version, default 2024-04
  CACHE_TTL_SECONDS  -> default 900 (15m)
  MAX_URLS_PER_FEED  -> default 5000 (keep < 50k)
  DEFAULT_PER_PAGE   -> default 1000 (capped to MAX_URLS_PER_FEED)
=================================== */

const APP_API_KEY = process.env.APP_API_KEY || "";
const APP_API_SECRET = process.env.APP_API_SECRET || "";
const HOST = process.env.HOST || "";
const SCOPES = process.env.SCOPES || "read_products,read_translations";

const API_VERSION = process.env.API_VERSION || "2024-04";
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 900);
const MAX_URLS_PER_FEED = Number(process.env.MAX_URLS_PER_FEED || 5000);
const DEFAULT_PER_PAGE = Math.min(Number(process.env.DEFAULT_PER_PAGE || 1000), MAX_URLS_PER_FEED);

// In-memory token store per shop (replace with Redis for production)
const tokenStore = new Map(); // shop => { accessToken, installedAt }

// Simple in-memory response cache
const responseCache = new Map(); // key => { body, expiresAt }

/* ========== Helpers ========== */

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
  if (h.startsWith("iw.")) return "he"; // Shopify uses 'he' not 'iw'
  if (h.endsWith(".nl")) return "nl";
  if (h.endsWith(".ch")) return "de"; // your CH site is DE content
  return "en";
}

// Extract numeric ID from gid://shopify/Thing/1234567890
function numericIdFromGid(gid) {
  if (!gid) return null;
  const parts = String(gid).split("/");
  return parts.length ? parts[parts.length - 1] : null;
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
    const tokenResp = await fetch(`https://${shop}/admin/oauth/access_token`, {
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

/* ========== Admin API fetchers (use per-shop token) ========== */

async function shopifyGraphQL(shop, accessToken, query, variables = {}) {
  const resp = await fetch(`https://${shop}/admin/api/${API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": accessToken,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ query, variables }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Admin API ${resp.status}: ${text}`);
  }
  return resp.json();
}

// Admin REST Translations API for a single product
async function fetchProductTranslations(shop, token, productNumericId, locale) {
  const url = `https://${shop}/admin/api/${API_VERSION}/translations.json?locale=${encodeURIComponent(locale)}&resource_type=Product&resource_id=${productNumericId}`;
  const resp = await fetch(url, {
    headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" }
  });
  if (!resp.ok) return null;
  const json = await resp.json();
  return json?.translations || null;
}

// Admin REST Translations API for a single collection
async function fetchCollectionTranslations(shop, token, collectionNumericId, locale) {
  const url = `https://${shop}/admin/api/${API_VERSION}/translations.json?locale=${encodeURIComponent(locale)}&resource_type=Collection&resource_id=${collectionNumericId}`;
  const resp = await fetch(url, {
    headers: { "X-Shopify-Access-Token": token, "Content-Type": "application/json" }
  });
  if (!resp.ok) return null;
  const json = await resp.json();
  return json?.translations || null;
}

async function getAllProductsWithImages(shop, accessToken) {
  const query = `
    query Products($first:Int!, $after:String) {
      products(first:$first, after:$after, query:"status:active") {
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
  const all = [];
  let after = null;
  let hasNext = true;
  while (hasNext) {
    const data = await shopifyGraphQL(shop, accessToken, query, { first: 100, after });
    const edges = data?.data?.products?.edges || [];
    for (const e of edges) all.push(e.node);
    hasNext = data?.data?.products?.pageInfo?.hasNextPage;
    after = edges.length ? edges[edges.length - 1].cursor : null;
  }
  return all;
}

async function getAllCollectionsWithImage(shop, accessToken) {
  const query = `
    query Collections($first:Int!, $after:String) {
      collections(first:$first, after:$after, query:"published_status:published") {
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
  const all = [];
  let after = null;
  let hasNext = true;
  while (hasNext) {
    const data = await shopifyGraphQL(shop, accessToken, query, { first: 200, after });
    const edges = data?.data?.collections?.edges || [];
    for (const e of edges) all.push(e.node);
    hasNext = data?.data?.collections?.pageInfo?.hasNextPage;
    after = edges.length ? edges[edges.length - 1].cursor : null;
  }
  return all;
}

/* ========== XML builders (with titles + captions, host-pref images) ========== */

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
    const type = (req.query.type || "all").toLowerCase();
    const includeCaptions = String(req.query.captions || "1") === "1";
    const preferHost = String(req.query.prefer_host || "1") === "1";
    const locale = getLocaleForHost(host, req.query.locale);

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

    // 1) Gather nodes (still loads all, then paginate — simplest for now)
    const baseNodes = [];

    if (type === "products" || type === "all") {
      const products = await getAllProductsWithImages(shop, tokenEntry.accessToken);
      for (const p of products) {
        const pageUrl = pageUrlForProduct(host, p.handle, p.onlineStoreUrl);
        const images = (p.images?.edges || []).map((e) => e.node);
        if (!images.length) continue;
        baseNodes.push({
          kind: "product",
          lastmod: p.updatedAt,
          pageUrl,
          productId: p.id,
          title: p.title,
          images // {id,url,altText}
        });
      }
    }

    if (type === "collections" || type === "all") {
      const collections = await getAllCollectionsWithImage(shop, tokenEntry.accessToken);
      for (const c of collections) {
        if (!c.image?.url) continue;
        const pageUrl = pageUrlForCollection(host, c.handle);
        baseNodes.push({
          kind: "collection",
          lastmod: c.updatedAt,
          pageUrl,
          collectionId: c.id,
          title: c.title,
          image: c.image // {id,url,altText}
        });
      }
    }

    // 2) Order newest first and slice the page
    baseNodes.sort((a, b) => (a.lastmod < b.lastmod ? 1 : -1));
    const start = (page - 1) * perPage;
    const end = start + perPage;
    const slice = baseNodes.slice(start, end);

    // 3) For THIS slice only, fetch translations and build XML
    const out = [];
    for (const node of slice) {
      if (node.kind === "product") {
        const numId = numericIdFromGid(node.productId);
        let titleTr = node.title;
        const imageAltMap = new Map(); // imageId => alt
        if (numId) {
          const trs = await fetchProductTranslations(shop, tokenEntry.accessToken, numId, locale);
          if (Array.isArray(trs)) {
            for (const t of trs) {
              // product title
              if (t.key === "title" && t.value) titleTr = t.value;
              // image alt keys can be "image[<id>].alt" OR "image.alt_text"
              if (t.key && t.value) {
                // image[123].alt
                const m = t.key.match(/^image\[(\d+)\]\.alt$/i);
                if (m) imageAltMap.set(m[1], t.value);
                // image.alt_text (rarely global)
                if (t.key === "image.alt_text") imageAltMap.set("*", t.value);
              }
            }
          }
        }
        const imgs = node.images.map((img) => {
          const imgIdNum = numericIdFromGid(img.id);
          const translatedAlt = (imgIdNum && imageAltMap.get(imgIdNum)) || imageAltMap.get("*") || img.altText || "";
          const imgUrl = preferHost ? preferHostImageUrl(img.url, host) : img.url;
          const title = translatedAlt || ""; // strict: only alt, no fallback to EN title
          const caption = includeCaptions && translatedAlt ? translatedAlt : "";
          return buildImageNode(imgUrl, title, caption);
        });
        out.push(buildUrlNode(node.pageUrl, node.lastmod, imgs));
      } else {
        // collection
        const numId = numericIdFromGid(node.collectionId);
        let titleTr = node.title;
        let imageAlt = node.image?.altText || "";
        if (numId) {
          const trs = await fetchCollectionTranslations(shop, tokenEntry.accessToken, numId, locale);
          if (Array.isArray(trs)) {
            for (const t of trs) {
              if (t.key === "title" && t.value) titleTr = t.value;
              const m = t.key && t.key.match(/^image\[(\d+)\]\.alt$/i);
              if (m && node.image?.id) {
                const imgIdNum = numericIdFromGid(node.image.id);
                if (imgIdNum && imgIdNum === m[1]) imageAlt = t.value;
              }
              if (t.key === "image.alt_text" && t.value) imageAlt = t.value;
            }
          }
        }
        const imgUrl = preferHost ? preferHostImageUrl(node.image.url, host) : node.image.url;
        const title = imageAlt || "";
        const caption = includeCaptions && imageAlt ? imageAlt : "";
        const imgs = [buildImageNode(imgUrl, title, caption)];
        out.push(buildUrlNode(node.pageUrl, node.lastmod, imgs));
      }
    }

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${out.join("\n")}
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

/* Optional: simple index that links to a few pages for all/type */
app.get("/image-index.xml", (req, res) => {
  const forwardedHost = req.get("x-forwarded-host") || req.get("host");
  const host = stripPort(forwardedHost);
  const shop = String(req.query.shop || "");
  const pages = Number(req.query.pages || 5);
  const type = String(req.query.type || "all");
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
