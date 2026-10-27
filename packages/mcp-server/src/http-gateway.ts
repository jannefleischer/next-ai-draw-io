/**
 * Multi-user HTTP gateway: serves the MCP server over Streamable HTTP for
 * clients like Open WebUI, one user per OAuth access token.
 *
 * The MCP server itself (index.ts) keeps one diagram session per process,
 * with files and auto-saves on disk. Rather than share one process, the
 * gateway runs one stdio process per user, each with its own data
 * directory, preview server port and relay tunnel, and forwards tools/list
 * and tools/call to it. The transport is stateless (no Mcp-Session-Id):
 * every request carries its token, and the diagram session is the
 * session_id the tools already pass around.
 *
 * Authorization follows the MCP spec (2026-07-28): the gateway is an OAuth
 * resource server, publishes Protected Resource Metadata (RFC 9728) and
 * accepts only tokens of OIDC_ISSUER with audience MCP_AUDIENCE. It never
 * passes them on: for the relay it exchanges them (RFC 8693) for a token
 * with audience RELAY_AUDIENCE, which the user's process reads from a file
 * whenever its tunnel connects.
 *
 * Env: GATEWAY_PORT (8080), PUBLIC_URL (e.g. https://drawio.ils.local),
 * OIDC_ISSUER, MCP_AUDIENCE, OIDC_CLIENT_ID / OIDC_CLIENT_SECRET (the
 * gateway's client, for the exchange), RELAY_URL, RELAY_AUDIENCE,
 * DATA_DIR (/data), USER_IDLE_MINUTES (120), MAX_USERS (50),
 * PREVIEW_PORT_BASE (7000).
 */

import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto"
import { mkdirSync, writeFileSync } from "node:fs"
import http from "node:http"
import { basename, dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js"
import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js"
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js"
import { log } from "./logger.ts"

const env = process.env
const PORT = Number(env.GATEWAY_PORT || 8080)
const PUBLIC_URL = (env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/+$/, "")
const RESOURCE = `${PUBLIC_URL}/mcp`
const ISSUER = (env.OIDC_ISSUER || "").replace(/\/+$/, "")
const AUDIENCE = env.MCP_AUDIENCE || "drawio-mcp"
const CLIENT_ID = env.OIDC_CLIENT_ID || AUDIENCE
const CLIENT_SECRET = env.OIDC_CLIENT_SECRET || ""
const RELAY_URL = (env.RELAY_URL || "").replace(/\/+$/, "")
const RELAY_AUDIENCE = env.RELAY_AUDIENCE || "drawio"
const DATA_DIR = env.DATA_DIR || "/data"
const IDLE_MS = Number(env.USER_IDLE_MINUTES || 120) * 60_000
const MAX_USERS = Number(env.MAX_USERS || 50)
const PORT_BASE = Number(env.PREVIEW_PORT_BASE || 7000)
const USER_CLAIM = env.OIDC_USER_CLAIM || "email"

const HERE = dirname(fileURLToPath(import.meta.url))
// Compiled next to index.js; from the sources (tsx) index.ts
const SERVER_ENTRY = join(HERE, import.meta.url.endsWith(".ts") ? "index.ts" : "index.js")

// ---------- tokens ----------

let jwks = new Map<string, KeyObject>()
let jwksRead = 0

async function signingKey(kid: string): Promise<KeyObject | undefined> {
    if (!jwks.has(kid) && Date.now() - jwksRead > 60_000) {
        jwksRead = Date.now()
        try {
            const res = await fetch(`${ISSUER}/protocol/openid-connect/certs`, {
                signal: AbortSignal.timeout(10_000),
            })
            const keys = ((await res.json()) as { keys?: Record<string, string>[] }).keys ?? []
            jwks = new Map(
                keys
                    .filter((k) => k.kty === "RSA" && (k.use === "sig" || !k.use))
                    .map((k) => [k.kid, createPublicKey({ key: k, format: "jwk" })]),
            )
        } catch (err) {
            log.warn(`Could not read the issuer's keys: ${String(err)}`)
        }
    }
    return jwks.get(kid)
}

const b64json = (part: string) => JSON.parse(Buffer.from(part, "base64url").toString())

/** The user a valid access token names, or null */
export async function tokenUser(token: string): Promise<string | null> {
    const m = token.match(/^([\w-]+)\.([\w-]+)\.([\w-]+)$/)
    if (!m || !ISSUER) return null
    let head: { alg?: string; kid?: string }
    let claims: Record<string, unknown>
    try {
        head = b64json(m[1])
        claims = b64json(m[2])
    } catch {
        return null
    }
    if (head.alg !== "RS256" || typeof head.kid !== "string") return null
    const key = await signingKey(head.kid)
    if (!key || !verify("RSA-SHA256", Buffer.from(`${m[1]}.${m[2]}`), key, Buffer.from(m[3], "base64url"))) {
        return null
    }
    const now = Date.now() / 1000
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
    if (
        claims.iss !== ISSUER ||
        !aud.includes(AUDIENCE) ||
        typeof claims.exp !== "number" ||
        claims.exp < now - 30 ||
        (typeof claims.nbf === "number" && claims.nbf > now + 30)
    ) {
        return null
    }
    const user = claims[USER_CLAIM]
    return typeof user === "string" && user ? user : null
}

/** RFC 8693: the user's token for the relay; null when the exchange fails */
async function exchangeForRelay(subjectToken: string): Promise<{ token: string; exp: number } | null> {
    const body = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: subjectToken,
        subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        audience: RELAY_AUDIENCE,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
    })
    try {
        const res = await fetch(`${ISSUER}/protocol/openid-connect/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body,
            signal: AbortSignal.timeout(10_000),
        })
        if (!res.ok) {
            log.warn(`Token exchange refused: ${res.status} ${(await res.text()).slice(0, 200)}`)
            return null
        }
        const data = (await res.json()) as { access_token?: string; expires_in?: number }
        if (!data.access_token) return null
        return { token: data.access_token, exp: Date.now() + (data.expires_in ?? 60) * 1000 }
    } catch (err) {
        log.warn(`Token exchange failed: ${String(err)}`)
        return null
    }
}

// ---------- one MCP process per user ----------

interface Worker {
    user: string
    dir: string
    port: number
    client: Client
    lastUsed: number
    relayTokenExp: number
}

const workers = new Map<string, Promise<Worker>>()
const usedPorts = new Set<number>()

function userDir(user: string): string {
    return join(DATA_DIR, "users", createHash("sha256").update(user).digest("hex").slice(0, 16))
}

async function startWorker(user: string): Promise<Worker> {
    if (workers.size > MAX_USERS) throw new Error("Too many users")
    let port = PORT_BASE
    while (usedPorts.has(port)) port++
    usedPorts.add(port)
    const dir = userDir(user)
    mkdirSync(join(dir, "files"), { recursive: true, mode: 0o700 })
    writeFileSync(join(dir, "owner"), `${user}\n`)
    // Only what the server needs: no gateway secrets in the child
    const childEnv: Record<string, string> = {
        PATH: env.PATH ?? "",
        HOME: dir,
        DRAWIO_DATA_DIR: dir,
        PORT: String(port),
        BROWSER: "none",
    }
    for (const name of ["DRAWIO_LANG", "DRAWIO_UI", "DRAWIO_DARK", "NODE_EXTRA_CA_CERTS", "RELAY_DRAWIO_URL", "LOG_LEVEL"]) {
        if (env[name]) childEnv[name] = env[name] as string
    }
    if (RELAY_URL) {
        childEnv.RELAY_URL = RELAY_URL
        childEnv.RELAY_TOKEN_FILE = join(dir, "relay-token")
    }
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: [SERVER_ENTRY],
        env: childEnv,
        cwd: join(dir, "files"),
        stderr: "pipe",
    })
    transport.stderr?.on("data", (d: Buffer) => {
        for (const line of d.toString().trimEnd().split("\n")) log.info(`[${user}] ${line}`)
    })
    const client = new Client({ name: "drawio-gateway", version: "1" })
    await client.connect(transport)
    transport.onclose = () => {
        workers.delete(user)
        usedPorts.delete(port)
        log.info(`Process of ${user} ended`)
    }
    log.info(`Started a process for ${user} (preview port ${port})`)
    return { user, dir, port, client, lastUsed: Date.now(), relayTokenExp: 0 }
}

function workerFor(user: string): Promise<Worker> {
    let w = workers.get(user)
    if (!w) {
        w = startWorker(user)
        w.catch(() => workers.delete(user))
        workers.set(user, w)
    }
    return w
}

setInterval(async () => {
    for (const w of workers.values()) {
        const worker = await w.catch(() => null)
        if (worker && Date.now() - worker.lastUsed > IDLE_MS) {
            log.info(`Stopping the idle process of ${worker.user}`)
            await worker.client.close()
        }
    }
}, 60_000).unref()

/**
 * File paths name the user's own files folder, never the gateway's disk:
 * load_diagram and export_diagram keep only the file name
 */
function confinePaths(args: Record<string, unknown> | undefined, worker: Worker) {
    if (!args) return args
    const out = { ...args }
    if (typeof out.path === "string") out.path = join(worker.dir, "files", basename(out.path))
    return out
}

// ---------- HTTP ----------

const metadata = () => ({
    resource: RESOURCE,
    authorization_servers: [ISSUER],
    bearer_methods_supported: ["header"],
    scopes_supported: ["openid"],
    resource_name: "draw.io (ILS)",
})

function unauthorized(res: http.ServerResponse, error?: string) {
    res.writeHead(401, {
        "Content-Type": "application/json",
        "WWW-Authenticate": `Bearer resource_metadata="${PUBLIC_URL}/.well-known/oauth-protected-resource/mcp"${error ? `, error="${error}"` : ""}`,
    })
    res.end(JSON.stringify({ error: error ?? "unauthorized" }))
}

async function handleMcp(req: http.IncomingMessage, res: http.ServerResponse) {
    const auth = req.headers.authorization ?? ""
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : ""
    const user = token ? await tokenUser(token) : null
    if (!user) return unauthorized(res, token ? "invalid_token" : undefined)

    let worker: Worker
    try {
        worker = await workerFor(user)
    } catch (err) {
        res.writeHead(503, { "Content-Type": "application/json" })
        res.end(JSON.stringify({ error: String(err) }))
        return
    }
    worker.lastUsed = Date.now()

    const server = new Server(
        { name: "drawio-gateway", version: "1" },
        { capabilities: { tools: {} }, instructions: worker.client.getInstructions() },
    )
    server.setRequestHandler(ListToolsRequestSchema, () => worker.client.listTools())
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        // A fresh relay token before a tool may open or reopen the tunnel
        if (RELAY_URL && worker.relayTokenExp - Date.now() < 60_000) {
            const relay = await exchangeForRelay(token)
            if (relay) {
                writeFileSync(join(worker.dir, "relay-token"), relay.token, { mode: 0o600 })
                worker.relayTokenExp = relay.exp
            }
        }
        return worker.client.callTool(
            { name: request.params.name, arguments: confinePaths(request.params.arguments, worker) },
            undefined,
            { timeout: 180_000 },
        )
    })
    const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
    })
    res.on("close", () => {
        void transport.close()
        void server.close()
    })
    await server.connect(transport)
    await transport.handleRequest(req, res)
}

const httpServer = http.createServer(async (req, res) => {
    try {
        const path = new URL(req.url || "/", "http://gateway").pathname
        if (path === "/healthz") {
            res.end("ok")
        } else if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp") {
            res.writeHead(200, { "Content-Type": "application/json" })
            res.end(JSON.stringify(metadata()))
        } else if (path === "/mcp") {
            await handleMcp(req, res)
        } else {
            res.writeHead(404)
            res.end("Not Found")
        }
    } catch (err) {
        log.error("Request failed:", err)
        if (!res.headersSent) res.writeHead(500)
        res.end()
    }
})

if (!ISSUER) {
    log.error("OIDC_ISSUER is not set")
    process.exit(1)
}
httpServer.listen(PORT, () => log.info(`MCP gateway on :${PORT}, resource ${RESOURCE}`))

const stop = async () => {
    httpServer.close()
    for (const w of workers.values()) await (await w.catch(() => null))?.client.close()
    process.exit(0)
}
process.on("SIGTERM", stop)
process.on("SIGINT", stop)
