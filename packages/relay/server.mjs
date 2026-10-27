// Relay between a draw.io host and MCP servers elsewhere (behind a firewall).
//
// Runs behind an auth proxy (oauth2-proxy) on the draw.io host's origin:
//   /mcp/                  token page of the signed-in user (proxy auth)
//   /mcp/t/<tunnel>/...    a preview tab's requests, forwarded to the MCP
//                          process that owns the tunnel (proxy auth, owner only)
//   /mcp-api/...           the MCP process: connect, long-poll, reply
//                          (proxy lets it through; the relay checks itself)
//
// The MCP process connects with an OIDC access token (Authorization: Bearer,
// audience OIDC_AUDIENCE, from one of OIDC_ISSUERS, signed with a key of
// OIDC_JWKS_URL) or, for accounts without OIDC, a personal relay token from
// the token page (X-Relay-Token). The token is checked on connect only: the
// tunnel then gets a secret of its own for its polls, so it outlives the
// short-lived access token while the tab stays open.
//
// The relay keeps no diagrams: the MCP process keeps its state and answers
// the tab's requests through the tunnel (packages/mcp-server/src/relay-tunnel.ts).
//
// Env: PORT (8080), DATA_DIR (/data), PUBLIC_URL (for the Origin check of
// the token page), USER_HEADERS (x-forwarded-email,x-forwarded-user: the
// first one present names the user; local accounts of the proxy have no email),
// OIDC_ISSUERS (comma-separated), OIDC_AUDIENCE (drawio), OIDC_JWKS_URL,
// OIDC_USER_CLAIM (email: must match what the proxy sends as the user).

import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify } from "node:crypto"
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs"
import http from "node:http"
import { join } from "node:path"

const PORT = Number(process.env.PORT || 8080)
const DATA_DIR = process.env.DATA_DIR || "/data"
const PUBLIC_URL = (process.env.PUBLIC_URL || "").replace(/\/+$/, "")
const USER_HEADERS = (process.env.USER_HEADERS || "x-forwarded-email,x-forwarded-user")
    .toLowerCase()
    .split(",")
    .map((h) => h.trim())
    .filter(Boolean)
const MAX_BODY = 12 * 1024 * 1024 // the MCP server takes 10 MiB, base64 adds a third
const POLL_WAIT_MS = 25_000
const REPLY_WAIT_MS = 60_000
const TUNNEL_IDLE_MS = 10 * 60_000
const MAX_TOKENS_PER_USER = 20
const MAX_TUNNELS_PER_USER = 10
const OIDC_ISSUERS = (process.env.OIDC_ISSUERS || "").split(",").map((s) => s.trim().replace(/\/+$/, "")).filter(Boolean)
const OIDC_AUDIENCE = process.env.OIDC_AUDIENCE || "drawio"
const OIDC_JWKS_URL = process.env.OIDC_JWKS_URL || ""
const OIDC_USER_CLAIM = process.env.OIDC_USER_CLAIM || "email"

const log = (...a) => console.log(new Date().toISOString(), ...a)

// ---------- tokens (data/tokens.json, only hashes) ----------

const TOKENS_FILE = join(DATA_DIR, "tokens.json")
mkdirSync(DATA_DIR, { recursive: true })
let tokens = []
try {
    tokens = JSON.parse(readFileSync(TOKENS_FILE, "utf8"))
} catch {}

function saveTokens() {
    writeFileSync(`${TOKENS_FILE}.tmp`, JSON.stringify(tokens, null, 1), { mode: 0o600 })
    renameSync(`${TOKENS_FILE}.tmp`, TOKENS_FILE)
}

const sha = (s) => createHash("sha256").update(s).digest("hex")

function tokenOwner(token) {
    if (typeof token !== "string" || !/^dmr_[0-9a-f]{40}$/.test(token)) return null
    const hash = Buffer.from(sha(token), "hex")
    const hit = tokens.find((t) => timingSafeEqual(Buffer.from(t.hash, "hex"), hash))
    if (!hit) return null
    hit.used = new Date().toISOString().slice(0, 10)
    return hit.user
}

// ---------- OIDC access tokens ----------

// Keys of OIDC_JWKS_URL by kid. Read again for an unknown kid (a rotation),
// at most once a minute.
let jwks = new Map()
let jwksRead = 0

async function signingKey(kid) {
    if (!jwks.has(kid) && Date.now() - jwksRead > 60_000) {
        jwksRead = Date.now()
        try {
            const res = await fetch(OIDC_JWKS_URL, { signal: AbortSignal.timeout(10_000) })
            const keys = (await res.json()).keys || []
            jwks = new Map(
                keys
                    .filter((k) => k.kty === "RSA" && (k.use === "sig" || !k.use))
                    .map((k) => [k.kid, createPublicKey({ key: k, format: "jwk" })]),
            )
        } catch (err) {
            log("jwks read failed", String(err))
        }
    }
    return jwks.get(kid)
}

const b64json = (part) => JSON.parse(Buffer.from(part, "base64url").toString())

/** The user an access token names, or null when it is not valid for us */
async function bearerOwner(header) {
    const m = typeof header === "string" && header.match(/^Bearer ([\w-]+)\.([\w-]+)\.([\w-]+)$/)
    if (!m || !OIDC_JWKS_URL || OIDC_ISSUERS.length === 0) return null
    let head
    let claims
    try {
        head = b64json(m[1])
        claims = b64json(m[2])
    } catch {
        return null
    }
    if (head.alg !== "RS256") return null
    const key = await signingKey(head.kid)
    if (!key || !verify("RSA-SHA256", Buffer.from(`${m[1]}.${m[2]}`), key, Buffer.from(m[3], "base64url"))) {
        return null
    }
    const now = Date.now() / 1000
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
    if (
        !OIDC_ISSUERS.includes(claims.iss) ||
        !aud.includes(OIDC_AUDIENCE) ||
        typeof claims.exp !== "number" ||
        claims.exp < now - 30 ||
        (typeof claims.nbf === "number" && claims.nbf > now + 30)
    ) {
        return null
    }
    const user = claims[OIDC_USER_CLAIM]
    return typeof user === "string" && user ? user : null
}

// ---------- tunnels (memory) ----------

/** id -> { user, secret, waiting: [res], queue: [req], pending: Map(id -> res), seen } */
const tunnels = new Map()

function tunnelFor(id, user) {
    const t = tunnels.get(id)
    return t && t.user === user ? t : null
}

setInterval(() => {
    const now = Date.now()
    for (const [id, t] of tunnels) {
        if (now - t.seen > TUNNEL_IDLE_MS && t.waiting.length === 0) {
            for (const res of t.pending.values()) send(res, 504, "MCP server gone")
            tunnels.delete(id)
            log("tunnel closed", id.slice(0, 8), t.user)
        }
    }
}, 60_000).unref()

/** Hand a queued request to a waiting poll, if both exist */
function dispatch(t) {
    while (t.queue.length && t.waiting.length) {
        const poll = t.waiting.shift()
        if (poll.writableEnded) continue
        json(poll, 200, t.queue.shift())
    }
}

// ---------- helpers ----------

function send(res, status, text, headers = {}) {
    if (res.headersSent) return
    res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8", ...headers })
    res.end(text)
}

function json(res, status, value) {
    if (res.headersSent) return
    res.writeHead(status, { "Content-Type": "application/json", "Cache-Control": "no-store" })
    res.end(JSON.stringify(value))
}

function readBody(req, limit = MAX_BODY) {
    return new Promise((resolve, reject) => {
        const chunks = []
        let size = 0
        req.on("data", (c) => {
            size += c.length
            if (size > limit) {
                reject(Object.assign(new Error("too large"), { status: 413 }))
                req.destroy()
            } else chunks.push(c)
        })
        req.on("end", () => resolve(Buffer.concat(chunks)))
        req.on("error", reject)
    })
}

const esc = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c])

// ---------- MCP side: /mcp-api/ ----------

async function mcpApi(req, res, path) {
    if (path === "/mcp-api/connect" && req.method === "POST") {
        const user = (await bearerOwner(req.headers.authorization)) || tokenOwner(req.headers["x-relay-token"])
        if (!user) {
            return json(res, 401, { error: "invalid token" })
        }
        let body = {}
        try {
            body = JSON.parse((await readBody(req, 4096)).toString() || "{}")
        } catch {}
        let id = typeof body.resume === "string" && /^[0-9a-f]{32}$/.test(body.resume) ? body.resume : null
        const existing = id && tunnels.get(id)
        if (existing && existing.user !== user) id = null
        if (!id || !existing) {
            const own = [...tunnels.values()].filter((t) => t.user === user).length
            if (!id && own >= MAX_TUNNELS_PER_USER) return json(res, 429, { error: "too many tunnels" })
            id ||= randomBytes(16).toString("hex")
            tunnels.set(id, {
                user,
                secret: randomBytes(24).toString("hex"),
                waiting: [],
                queue: [],
                pending: new Map(),
                seen: Date.now(),
            })
            log("tunnel open", id.slice(0, 8), user)
        }
        const t = tunnels.get(id)
        t.seen = Date.now()
        return json(res, 200, { tunnel: id, secret: t.secret, prefix: `/mcp/t/${id}`, user })
    }

    // Polls and replies carry the tunnel's own secret
    const m = path.match(/^\/mcp-api\/t\/([0-9a-f]{32})\/(next|reply)$/)
    const t = m && tunnels.get(m[1])
    const given = Buffer.from(String(req.headers["x-tunnel-secret"] || ""))
    if (!t || given.length !== t.secret.length || !timingSafeEqual(given, Buffer.from(t.secret))) {
        return json(res, 404, { error: "unknown tunnel" })
    }
    t.seen = Date.now()

    if (m[2] === "next" && req.method === "GET") {
        t.waiting.push(res)
        const timer = setTimeout(() => {
            t.waiting = t.waiting.filter((r) => r !== res)
            if (!res.headersSent) {
                res.writeHead(204)
                res.end()
            }
        }, POLL_WAIT_MS)
        res.on("close", () => {
            clearTimeout(timer)
            t.waiting = t.waiting.filter((r) => r !== res)
        })
        return dispatch(t)
    }

    if (m[2] === "reply" && req.method === "POST") {
        const reply = JSON.parse((await readBody(req)).toString())
        const target = t.pending.get(reply.id)
        if (target) {
            t.pending.delete(reply.id)
            forwardReply(target, reply)
        }
        return json(res, 200, { ok: true })
    }
    json(res, 405, { error: "method not allowed" })
}

// Response headers passed on to the tab
const REPLY_HEADERS = ["content-type", "cache-control", "etag", "content-security-policy", "x-content-type-options"]

function forwardReply(res, reply) {
    const headers = {}
    for (const name of REPLY_HEADERS) {
        if (typeof reply.headers?.[name] === "string") headers[name] = reply.headers[name]
    }
    // The MCP server redirects to its own paths (/shell/?mcp=…): under the tunnel's prefix
    const location = reply.headers?.location
    if (typeof location === "string" && location.startsWith("/") && !location.startsWith("//")) {
        headers.location = res.ilsPrefix + location
    }
    const status = Number.isInteger(reply.status) && reply.status >= 200 && reply.status < 600 ? reply.status : 502
    if (res.headersSent) return
    res.writeHead(status, headers)
    res.end(Buffer.from(reply.body || "", "base64"))
}

// ---------- tab side: /mcp/t/<id>/... ----------

// Request headers passed on to the MCP server
const TAB_HEADERS = ["accept", "content-type", "if-none-match", "x-drawio-token"]

async function tabRequest(req, res, user, id, rest, search) {
    const t = tunnelFor(id, user)
    if (!t) {
        return send(res, 404, "Diese KI-Sitzung gibt es nicht (mehr), oder sie gehört einem anderen Konto.")
    }
    if (rest.split("/").some((seg) => seg === ".." || seg === ".")) return send(res, 400, "Bad Request")
    let body
    if (req.method !== "GET" && req.method !== "HEAD") {
        try {
            body = (await readBody(req)).toString("base64")
        } catch (e) {
            return send(res, e.status || 400, "Bad Request")
        }
    }
    const headers = {}
    for (const name of TAB_HEADERS) {
        if (typeof req.headers[name] === "string") headers[name] = req.headers[name]
    }
    const reqId = randomBytes(12).toString("hex")
    res.ilsPrefix = `/mcp/t/${id}`
    t.pending.set(reqId, res)
    t.queue.push({ id: reqId, method: req.method, path: rest + search, headers, body })
    const timer = setTimeout(() => {
        t.pending.delete(reqId)
        t.queue = t.queue.filter((q) => q.id !== reqId)
        send(res, 504, "Der MCP-Server antwortet nicht.")
    }, REPLY_WAIT_MS)
    res.on("close", () => {
        clearTimeout(timer)
        t.pending.delete(reqId)
    })
    dispatch(t)
}

// ---------- token page: /mcp/ ----------

function tokenPage(res, user, created) {
    const mine = tokens.filter((t) => t.user === user)
    const own = [...tunnels.entries()].filter(([, t]) => t.user === user)
    const rows = mine
        .map(
            (t) => `<tr><td>${esc(t.name)}</td><td>${esc(t.created)}</td><td>${esc(t.used || "–")}</td>
<td><form method="post" action="/mcp/tokens/delete"><input type="hidden" name="id" value="${esc(t.id)}">
<button>Widerrufen</button></form></td></tr>`,
        )
        .join("")
    const fresh = created
        ? `<div class="new"><p><b>Neuer Token</b> – wird nur jetzt angezeigt:</p><code>${esc(created)}</code>
<p>In der MCP-Konfiguration als <code>RELAY_TOKEN</code> eintragen, dazu <code>RELAY_URL=${esc(PUBLIC_URL || "https://…")}</code>.</p></div>`
        : ""
    res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    })
    res.end(`<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>KI-Zugang zu draw.io</title>
<style>body{font:15px/1.5 system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;color:#222}
table{border-collapse:collapse;width:100%}td,th{padding:.3rem .5rem;border-bottom:1px solid #ddd;text-align:left}
code{background:#f3f3f3;padding:.1rem .3rem;word-break:break-all}.new{background:#eef7ee;padding:.5rem 1rem;border-radius:6px}
input[type=text]{padding:.3rem;width:16rem}button{padding:.3rem .8rem}</style>
<h1>KI-Zugang zu draw.io</h1>
<p>Angemeldet als <b>${esc(user)}</b>. Mit einem persönlichen Token verbindet sich ein MCP-Server (z.&nbsp;B. in Claude
Desktop) mit diesem draw.io. Er sieht und bearbeitet nur die KI-Sitzungen, die er selbst startet, und nur du kannst sie öffnen.</p>
${fresh}
<h2>Tokens</h2>
${mine.length ? `<table><tr><th>Name</th><th>Erstellt</th><th>Zuletzt genutzt</th><th></th></tr>${rows}</table>` : "<p>Noch keine.</p>"}
<form method="post" action="/mcp/tokens"><p><input type="text" name="name" maxlength="60" placeholder="Name, z. B. Laptop" required>
<button>Token erzeugen</button></p></form>
<h2>Verbundene MCP-Server</h2><p>${own.length ? `${own.length} verbunden.` : "Keiner."}</p>
<p><a href="/">Zurück zu draw.io</a></p></html>`)
}

async function tokenAction(req, res, user, path) {
    // Lax cookies keep cross-site POSTs out already; this also stops same-site ones
    const origin = req.headers.origin
    if (PUBLIC_URL && origin !== PUBLIC_URL) return send(res, 403, "Forbidden")
    let form
    try {
        form = new URLSearchParams((await readBody(req, 4096)).toString())
    } catch {
        return send(res, 400, "Bad Request")
    }
    if (path === "/mcp/tokens") {
        if (tokens.filter((t) => t.user === user).length >= MAX_TOKENS_PER_USER) return send(res, 429, "Zu viele Tokens")
        const token = `dmr_${randomBytes(20).toString("hex")}`
        tokens.push({
            id: randomBytes(8).toString("hex"),
            user,
            name: (form.get("name") || "Token").slice(0, 60),
            created: new Date().toISOString().slice(0, 10),
            hash: sha(token),
        })
        saveTokens()
        log("token created", user)
        return tokenPage(res, user, token)
    }
    if (path === "/mcp/tokens/delete") {
        const id = form.get("id")
        tokens = tokens.filter((t) => !(t.user === user && t.id === id))
        saveTokens()
        log("token revoked", user)
        res.writeHead(303, { Location: "/mcp/" })
        return res.end()
    }
    send(res, 404, "Not Found")
}

// ---------- routing ----------

const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url || "/", "http://relay")
        const path = url.pathname
        if (path === "/healthz") return send(res, 200, "ok")
        if (path.startsWith("/mcp-api/")) return await mcpApi(req, res, path)

        // Everything else needs the proxy's identity
        const user = USER_HEADERS.map((h) => req.headers[h]).find((v) => typeof v === "string" && v)
        if (!user) return send(res, 401, "Not signed in")

        const m = path.match(/^\/mcp\/t\/([0-9a-f]{32})(\/.*)?$/)
        if (m) return await tabRequest(req, res, user, m[1], m[2] || "/", url.search)
        if (path === "/mcp" || path === "/mcp/") {
            if (req.method !== "GET") return send(res, 405, "Method Not Allowed")
            return tokenPage(res, user)
        }
        if (req.method === "POST" && path.startsWith("/mcp/tokens")) return await tokenAction(req, res, user, path)
        send(res, 404, "Not Found")
    } catch (err) {
        log("error", err)
        send(res, err.status || 500, "Error")
    }
})

server.requestTimeout = 0 // long polls
server.listen(PORT, () => log(`relay on :${PORT}, data in ${DATA_DIR}`))
