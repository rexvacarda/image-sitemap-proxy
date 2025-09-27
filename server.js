import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

const app = express();

/* ========= CONFIG via ENV =========
Required:
  SHOP               -> your admin domain, e.g. smelltoimpress.myshopify.com
  ADMIN_API_TOKEN    -> Admin API token with read_products + read_collections
  SHARED_SECRET      -> App Proxy "Shared secret" (from Shopify)
Optional:
  API_VERSION        -> e.g. 2024-04 (default)
  CACHE_TTL_SECONDS  -> e.g. 3600 (1h)
  MAX_URLS_PER_FEED  -> e.g. 45000 (keep < 50k)
=================================== */

const SHOP = process.env.SHOP; // e.g., smelltoimpress.myshopify.com
const ADMIN_API_TOKEN = process.env.ADMIN_API_TOKEN;
const API_VERSION = process.env.API_VERSION || "2024-04";
const SHARED_SECRET = process.env.SHARED_SECRET;
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 3600);
const MAX_URLS_PER_FEED = Number(process.env.MAX_URLS_PER_FEED || 45000);

// Ensure required envs exist at startup
["SHOP", "ADMIN_API_TOKEN", "SHARED_SECRET"].forEach((k) => {
  if (!process.env[k]) {
    console.error(`[startup] Missing env var ${k}`);
  }
});

/* ========== Helpers ========== */

function verifyAppProxy(req) {
  // Shopify App Proxy passes all query params + `signature`
  const { signature, ...params } = req.query;
  if (!SHARED_SECRET || !signature) return false;

  const sorted = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("");

  const digest = crypto
    .createHmac("sha256", SHARED_SECRET)
    .update(sorted)
    .digest("hex");

  return signature === digest;
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

function pageUrlForProduct(host, handle, onlineStoreUrl) {
  const h = stripPort(host);
  if (onlineStoreUrl) return onlineStoreUrl.replace(/^https?:\/\/[^/]+/, `https://${h}`);
  return `https://${h}/products/${handle}`;
}

function pageUrlForCollection(host, handle) {
  const h = stripPort(host);
  return `https://${h}/collections/${handle}`;
}

/* ========== Shopify Admin GraphQL fetchers ========== */

async function shopifyGraphQL(query, variables = {}) {
  const resp = await fetch(`https://${SHOP}/admin/api/${API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "X-Shopify-Access-Token": ADMIN_API_TOKEN,
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

async function getAllProductsWithImages() {
  const query = `
    query Products($first:Int!, $after:String) {
      products(first:$first, after:$after, query:"status:active") {
        edges {
          cursor
          node {
            title
            handle
            onlineStoreUrl
            images(first:50) {
              edges { node { url altText } }
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
    const data = await shopifyGraphQL(query, { first: 100, after });
    const edges = data?.data?.products?.edges || [];
    for (const e of edges) all.push(e.node);
    hasNext = data?.data?.products?.pageInfo?.hasNextPage;
    after = edges.length ? edges[edges.length - 1].cursor : null;
  }
  return all;
}

async function getAllCollectionsWithImage() {
  const query = `
    query Collections($first:Int!, $after:String) {
      collections(first:$first, after:$after, query:"published_status:published") {
        edges {
          cursor
          node {
            title
            handle
            image { url altText }
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
    const data = await shopifyGraphQL(query, { first: 200, after });
    const edges = data?.data?.collections?.edges || [];
    for (const e of edges) all.push(e.node);
    hasNext = data?.data?.collections?.pageInfo?.hasNextPage;
    after = edges.length ? edges[edges.length - 1].cursor : null;
  }
  return all;
}

/* ========== XML builders ========== */

function buildImageNode(loc, title) {
  return `
    <image:image>
      <image:loc>${x(loc)}</image:loc>
      ${title ? `<image:title>${x(title)}</image:title>` : ""}
    </image:image>`;
}

function buildUrlNode(pageLoc, imageNodes) {
  return `
  <url>
    <loc>${x(pageLoc)}</loc>
    ${imageNodes.join("")}
  </url>`;
}

/* ========== Main endpoint ========== */
/*
  Shopify proxies:
    /apps/sitemaps/image.xml       -> our server route /image.xml
    /apps/sitemaps/image-index.xml -> our server route /image-index.xml

  Optional query:
    - type=products|collections|all (default: all)
    - page=1..N (simple pagination after combining URLs)
*/
app.get("/image.xml", async (req, res) => {
  try {
    if (!verifyAppProxy(req)) return res.status(401).send("Invalid signature");

    const host = req.get("x-forwarded-host") || req.get("host");
    const type = (req.query.type || "all").toLowerCase(); // products|collections|all
    const page = Math.max(parseInt(req.query.page || "1", 10), 1);

    // Fetch data based on type
    const nodes = [];

    if (type === "products" || type === "all") {
      const products = await getAllProductsWithImages();
      for (const p of products) {
        const pageUrl = pageUrlForProduct(host, p.handle, p.onlineStoreUrl);
        const images = (p.images?.edges || []).map((e) => e.node);
        if (!images.length) continue; // skip products with no images
        const imageNodes = images.map((img) => buildImageNode(img.url, img.altText || p.title));
        nodes.push(buildUrlNode(pageUrl, imageNodes));
      }
    }

    if (type === "collections" || type === "all") {
      const collections = await getAllCollectionsWithImage();
      for (const c of collections) {
        if (!c.image?.url) continue; // skip collections without image
        const pageUrl = pageUrlForCollection(host, c.handle);
        const imageNodes = [buildImageNode(c.image.url, c.image.altText || c.title)];
        nodes.push(buildUrlNode(pageUrl, imageNodes));
      }
    }

    // Pagination (simple chunking)
    const start = (page - 1) * MAX_URLS_PER_FEED;
    const end = start + MAX_URLS_PER_FEED;
    const slice = nodes.slice(start, end);

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset
  xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
  xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${slice.join("\n")}
</urlset>`;

    setXmlHeaders(res);
    return res.status(200).send(xml);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Sitemap generation error");
  }
});

/* ========== Optional: index for paginated feeds ========== */
app.get("/image-index.xml", (req, res) => {
  const host = stripPort(req.get("x-forwarded-host") || req.get("host"));
  const urls = Array.from({ length: 5 }, (_, i) => i + 1).map(
    (n) => `<sitemap><loc>https://${host}/apps/sitemaps/image.xml?type=all&page=${n}</loc></sitemap>`
  );
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</sitemapindex>`;
  setXmlHeaders(res);
  return res.status(200).send(xml);
});

/* ========== Health & Root ========== */
app.get("/health", (_req, res) => res.type("text/plain").send("ok"));
app.get("/", (_req, res) => {
  res
    .type("text/plain")
    .send("Image Sitemap Proxy is running. Use /health or call via Shopify App Proxy at /apps/sitemaps/image.xml");
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Image sitemap proxy on :${port}`));
