import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";
import { URL } from "url";

const app = express();

/* ========= CONFIG via ENV (HYBRID) =========
Required:
  SHOP
  ADMIN_API_TOKEN
  SHARED_SECRET
Optional (recommended):
  STOREFRONT_TOKEN   -> enables fully localized fetch via Storefront API
  SF_API_VERSION     -> default 2024-07
  API_VERSION        -> default 2024-04
  CACHE_TTL_SECONDS  -> default 900
  MAX_URLS_PER_FEED  -> default 5000
  DEFAULT_PER_PAGE   -> default 200
  HTTP_TIMEOUT_MS    -> default 12000
  TRANS_CONCURRENCY  -> default 8
  DISABLE_HMAC       -> "1" to bypass proxy HMAC (local testing only)
============================================= */

const SHOP = process.env.SHOP || "";
const ADMIN_API_TOKEN = process.env.ADMIN_API_TOKEN || "";
const SHARED_SECRET = process.env.SHARED_SECRET || "";
const STOREFRONT_TOKEN = process.env.STOREFRONT_TOKEN || "";
const SF_API_VERSION = process.env.SF_API_VERSION || "2024-07";

const API_VERSION = process.env.API_VERSION || "2024-04";
const CACHE_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 900);
const MAX_URLS_PER_FEED = Number(process.env.MAX_URLS_PER_FEED || 5000);
const DEFAULT_PER_PAGE = Math.min(Number(process.env.DEFAULT_PER_PAGE || 200), MAX_URLS_PER_FEED);
const HTTP_TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 12000);
const TRANS_CONCURRENCY = Math.max(1, Number(process.env.TRANS_CONCURRENCY || 8));
const DISABLE_HMAC = String(process.env.DISABLE_HMAC || "0") === "1";

const responseCache = new Map();

function cacheKey(parts){return Object.entries(parts).map(([k,v])=>`${k}=${v}`).sort().join("|");}
function setXmlHeaders(res){res.set("Content-Type","application/xml; charset=utf-8");res.set("Cache-Control",`public, max-age=${CACHE_TTL_SECONDS}`);}
function x(s=""){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function stripPort(host){return (host||"").replace(/:.+$/,"");}
function preferHostImageUrl(originalUrl, host){
  try{
    const u=new URL(originalUrl);
    if(u.hostname!=="cdn.shopify.com") return originalUrl;
    const p=u.pathname;
    const iP=p.indexOf("/products/"); const iF=p.indexOf("/files/");
    let rebuilt=null;
    if(iP!==-1) rebuilt=`/cdn/shop${p.substring(iP)}${u.search||""}`;
    else if(iF!==-1) rebuilt=`/cdn/shop${p.substring(iF)}${u.search||""}`;
    return rebuilt?`https://${host}${rebuilt}`:originalUrl;
  }catch{return originalUrl;}
}
function pageUrlForProduct(host, handle, onlineStoreUrl){
  const h=stripPort(host);
  if(onlineStoreUrl) return onlineStoreUrl.replace(/^https?:\/\/[^/]+/,`https://${h}`);
  return `https://${h}/products/${handle}`;
}
function pageUrlForCollection(host, handle){
  const h=stripPort(host);
  return `https://${h}/collections/${handle}`;
}

/** Shopify App Proxy HMAC verify */
function verifyProxyHmac(req){
  if (DISABLE_HMAC) return true;
  const query = { ...req.query };
  const provided = (query.signature || query.sig || "").toString().toLowerCase();
  delete query.signature; delete query.sig;
  if (!SHARED_SECRET || !provided) return false;
  const payload = Object.keys(query).sort().map(k => `${k}=${query[k]}`).join("");
  const expected = crypto.createHmac("sha256", SHARED_SECRET).update(payload).digest("hex").toLowerCase();
  try {
    const a = Buffer.from(expected, "hex");
    const b = Buffer.from(provided, "hex");
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function getLocaleForHost(host, override){
  if (override) return override.toLowerCase();
  const h=(host||"").toLowerCase();
  if (h.endsWith(".fr")) return "fr";
  if (h.endsWith(".it")) return "it";
  if (h.startsWith("ko.")) return "ko";
  if (h.startsWith("ar.")) return "ar";
  if (h.startsWith("iw.")) return "he";
  if (h.endsWith(".nl")) return "nl";
  if (h.endsWith(".ch")) return "de";
  return "en";
}
function numericIdFromGid(gid){ if(!gid) return null; const parts=String(gid).split("/"); return parts.length?parts[parts.length-1]:null; }
async function timedFetch(url, opts={}, timeoutMs=HTTP_TIMEOUT_MS){
  const c=new AbortController(); const t=setTimeout(()=>c.abort(),timeoutMs);
  try{return await fetch(url,{...opts,signal:c.signal});} finally{clearTimeout(t);}
}
async function pMap(items, limit, mapper){
  const ret=[]; const running=[];
  for(const item of items){
    const p=Promise.resolve().then(()=>mapper(item));
    ret.push(p);
    const e=p.then(()=>running.splice(running.indexOf(e),1));
    running.push(e);
    if(running.length>=limit) await Promise.race(running);
  }
  return Promise.all(ret);
}

/* ---------- Storefront API (localized) ---------- */

async function sfGraphQL(query, variables, acceptLanguage){
  const resp = await timedFetch(`https://${SHOP}/api/${SF_API_VERSION}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Storefront-Access-Token": STOREFRONT_TOKEN,
      ...(acceptLanguage ? { "Accept-Language": acceptLanguage } : {})
    },
    body: JSON.stringify({ query, variables })
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Storefront API ${resp.status}: ${text}`);
  }
  return resp.json();
}

// Return newest-first slice, localized (title, altText) – fetch a larger page then slice.
async function sfGetProductsSlice(offset, limit, acceptLanguage){
  const pageSize = Math.min(Math.max(limit, 50), 250);
  const data = await sfGraphQL(`
    query($first:Int!) {
      products(first:$first, sortKey:UPDATED_AT, reverse:true) {
        nodes {
          handle
          title
          onlineStoreUrl
          updatedAt
          images(first:50) { nodes { url altText } }
        }
      }
    }`, { first: pageSize + offset }, acceptLanguage);
  const nodes = data?.data?.products?.nodes || [];
  return nodes.slice(offset, offset + limit);
}

async function sfGetCollectionsSlice(offset, limit, acceptLanguage){
  const pageSize = Math.min(Math.max(limit, 50), 250);
  const data = await sfGraphQL(`
    query($first:Int!) {
      collections(first:$first, sortKey:UPDATED_AT, reverse:true) {
        nodes {
          handle
          title
          updatedAt
          image { url altText }
        }
      }
    }`, { first: pageSize + offset }, acceptLanguage);
  const nodes = data?.data?.collections?.nodes || [];
  return nodes.slice(offset, offset + limit);
}

/* ---------- Admin API (fallback) ---------- */

async function gqlPagedSlice({ query, selectEdges, first, offset, take }){
  let after=null; let skipped=0; const out=[];
  while(out.length<take){
    const resp=await timedFetch(`https://${SHOP}/admin/api/${API_VERSION}/graphql.json`,{
      method:"POST",
      headers:{ "X-Shopify-Access-Token":ADMIN_API_TOKEN,"Content-Type":"application/json"},
      body:JSON.stringify({ query, variables:{ first, after }})
    });
    if(!resp.ok){ const text=await resp.text(); throw new Error(`Admin API ${resp.status}: ${text}`); }
    const json=await resp.json();
    const edges=selectEdges(json)||[];
    if(!edges.length) break;
    for(const e of edges){
      if(skipped<offset) skipped+=1;
      else if(out.length<take) out.push(e.node);
    }
    const pageInfo=edges.length?json.data[Object.keys(json.data)[0]].pageInfo:{hasNextPage:false};
    if(!pageInfo?.hasNextPage||out.length>=take) break;
    after=edges[edges.length-1].cursor;
  }
  return out;
}

async function getProductsSlice(offset, limit){
  const query=`
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
            images(first:50) { edges { node { id url altText } } }
          }
        }
        pageInfo { hasNextPage }
      }
    }`;
  return gqlPagedSlice({ query, selectEdges:j=>j?.data?.products?.edges, first:100, offset, take:limit });
}

async function getCollectionsSlice(offset, limit){
  const query=`
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
    }`;
  return gqlPagedSlice({ query, selectEdges:j=>j?.data?.collections?.edges, first:200, offset, take:limit });
}

/* ---------- XML builders ---------- */

function buildImageNode(loc, title, caption){
  return `
        <image:image>
          <image:loc>${x(loc)}</image:loc>
          <image:title>${x(title || "")}</image:title>
          <image:caption>${x(caption || "")}</image:caption>
        </image:image>`;
}
function buildUrlNode(pageLoc, lastmodISO, imageNodes){
  return `<url>
      <loc>${x(pageLoc)}</loc>
      ${lastmodISO?`<lastmod>${x(lastmodISO)}</lastmod>`:""}${imageNodes.join("")}
    </url>`;
}

/* ---------- Main App Proxy endpoints ---------- */

app.get("/image.xml", async (req,res)=>{
  try{
    if(!verifyProxyHmac(req)) return res.status(401).send("Invalid signature");

    const forwardedHost=req.get("x-forwarded-host")||req.get("host");
    const host=stripPort(forwardedHost);

    const page=Math.max(parseInt(req.query.page||"1",10),1);
    const perPageRaw=Math.max(parseInt(req.query.per_page||String(DEFAULT_PER_PAGE),10),1);
    const perPage=Math.min(perPageRaw,MAX_URLS_PER_FEED);
    const type=(req.query.type||"all").toLowerCase(); // products|collections|all
    const preferHost=String(req.query.prefer_host||"1")==="1";
    const locale=getLocaleForHost(host, req.query.locale);
    const key=cacheKey({route:"image.xml",host,page,perPage,type,preferHost,locale});
    const hit=responseCache.get(key); const now=Date.now();
    if(hit && hit.expiresAt>now){ setXmlHeaders(res); return res.status(200).send(hit.body); }

    const offset=(page-1)*perPage;
    const nodes=[];
    const useSF = !!STOREFRONT_TOKEN;

    // PRODUCTS
    if(type==="products"||type==="all"){
      const products = useSF
        ? await sfGetProductsSlice(offset, perPage, locale)
        : await getProductsSlice(offset, perPage);

      for (const p of products){
        const handle = p.handle;
        const pageUrl = pageUrlForProduct(host, handle, p.onlineStoreUrl);
        const updatedAt = p.updatedAt;
        const imagesArr = useSF ? (p.images?.nodes || []) : ((p.images?.edges || []).map(e=>e.node));
        if(!imagesArr.length) continue;

        const localizedTitle = p.title || "";
        const imageNodes = imagesArr.map(img=>{
          const imgUrl = preferHost ? preferHostImageUrl(img.url, host) : img.url;
          const resolved = (img.altText && img.altText.trim()) ? img.altText : localizedTitle;
          return buildImageNode(imgUrl, resolved, resolved);
        });

        nodes.push(buildUrlNode(pageUrl, updatedAt, imageNodes));
      }
    }

    // COLLECTIONS
    if(type==="collections"||type==="all"){
      const collections = useSF
        ? await sfGetCollectionsSlice(offset, perPage, locale)
        : await getCollectionsSlice(offset, perPage);

      for (const c of collections){
        const pageUrl = pageUrlForCollection(host, c.handle);
        const updatedAt = c.updatedAt;
        const imgObj = c.image;
        if (!imgObj?.url) continue;

        const imgUrl = preferHost ? preferHostImageUrl(imgObj.url, host) : imgObj.url;
        const resolved = (imgObj.altText && imgObj.altText.trim()) ? imgObj.altText : (c.title || "");
        const imageNodes = [buildImageNode(imgUrl, resolved, resolved)];

        nodes.push(buildUrlNode(pageUrl, updatedAt, imageNodes));
      }
    }

    const xml=`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
${nodes.join("\n")}
</urlset>`;

    responseCache.set(key,{ body:xml, expiresAt: now + CACHE_TTL_SECONDS*1000 });
    setXmlHeaders(res);
    return res.status(200).send(xml);

  }catch(e){
    console.error(e);
    return res.status(500).send("Sitemap generation error");
  }
});

/* ---------- Diagnostics ---------- */

app.get("/echo", (req, res) => {
  res.status(200).type("text/plain").send(`echo ok | host=${req.get("x-forwarded-host") || req.get("host")} | path=${req.path}`);
});

app.get("/proxy-self-test", (req, res) => {
  const ok = verifyProxyHmac(req);
  res.status(ok ? 200 : 401).type("text/plain").send(ok ? "proxy hmac ok" : "proxy hmac invalid");
});

app.get("/proxy-debug", (req, res) => {
  const q = { ...req.query };
  const given = (q.signature || q.sig || "").toString().toLowerCase();
  delete q.signature; delete q.sig;
  const payload = Object.keys(q).sort().map(k => `${k}=${q[k]}`).join("");
  const expected = SHARED_SECRET
    ? crypto.createHmac("sha256", SHARED_SECRET).update(payload).digest("hex").toLowerCase()
    : "(SHARED_SECRET MISSING)";
  res.type("text/plain").send(
    [
      `host: ${req.get("host")}`,
      `path: ${req.path}`,
      `payload: ${payload}`,
      `expected signature: ${expected}`,
      `given signature:    ${given}`,
      `match: ${expected === given}`,
    ].join("\n")
  );
});

/* ---------- Index, health ---------- */
app.get("/image-index.xml",(req,res)=>{
  const forwardedHost=req.get("x-forwarded-host")||req.get("host");
  const host=stripPort(forwardedHost);
  const pages=Number(req.query.pages||5);
  const type=String(req.query.type||"products");
  const perPage=Number(req.query.per_page||DEFAULT_PER_PAGE);
  const locale=req.query.locale?`&locale=${encodeURIComponent(req.query.locale)}`:"";
  const urls=Array.from({length:pages},(_,i)=>i+1).map(
    n=>`<sitemap><loc>https://${host}/apps/sitemaps/image.xml?type=${encodeURIComponent(type)}&page=${n}&per_page=${perPage}${locale}</loc></sitemap>`
  );
  const xml=`<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.join("\n")}
</sitemapindex>`;
  setXmlHeaders(res);
  return res.status(200).send(xml);
});

app.get("/health",(_req,res)=>res.type("text/plain").send("ok"));
app.get("/",(_req,res)=>res.type("text/plain").send("Image Sitemap Proxy (hybrid) running."));

app.use((err, _req, res, _next) => {
  console.error("[unhandled]", err);
  res.status(500).type("text/plain").send(`Server error: ${err?.message || "unknown"}`);
});

const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`Image sitemap proxy (hybrid) on :${port}`));
