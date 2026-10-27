/**
 * Relay tunnel: lets a preview tab on a remote draw.io host (the relay,
 * packages/relay) reach this process's HTTP server. The process connects
 * outbound with a personal token, long-polls the relay for the tab's
 * requests, replays each against 127.0.0.1 and posts the answer back. The
 * state stays here; the relay only forwards, and only for the token's owner.
 *
 * Set RELAY_URL (e.g. https://drawio.example.org) and RELAY_TOKEN: an OIDC
 * access token the relay accepts (sent as Bearer) or a personal relay token
 * from its token page (dmr_…). The token is needed to connect only; the
 * tunnel's polls carry the secret the relay hands out with it.
 */

import { readFile } from "node:fs/promises"
import http from "node:http"
import { log } from "./logger.ts"

/** Headers of the tab's request the local server needs */
const REQUEST_HEADERS = [
    "accept",
    "content-type",
    "if-none-match",
    "x-drawio-token",
]

// Several polls at once: the tab's requests (state poll, history, a
// shell.js download) are answered in parallel
const POLLERS = 4
const POLL_TIMEOUT_MS = 40_000

export interface RelayTunnel {
    /** Origin of the relay, e.g. https://drawio.example.org */
    origin: string
    /** Path the tab reaches this process under, e.g. /mcp/t/<id> */
    readonly prefix: string
    stop(): void
}

interface TunnelRequest {
    id: string
    method: string
    path: string
    headers: Record<string, string>
    body?: string // base64
}

/**
 * RELAY_TOKEN, or RELAY_TOKEN_FILE: a file read again on every connect, so
 * whoever writes it (the HTTP gateway) can keep a short-lived token fresh
 */
export function relayConfigFromEnv(
    env: NodeJS.ProcessEnv = process.env,
): { url: string; token: string | (() => Promise<string>) } | null {
    const url = (env.RELAY_URL ?? "").replace(/\/+$/, "")
    const file = env.RELAY_TOKEN_FILE ?? ""
    const token = env.RELAY_TOKEN ?? ""
    if (!url) return null
    if (file) {
        return { url, token: async () => (await readFile(file, "utf8")).trim() }
    }
    if (!token) {
        log.warn("RELAY_URL is set without RELAY_TOKEN; the relay stays off")
        return null
    }
    return { url, token }
}

/** The headers that authenticate a connect with this token */
export function relayAuthHeaders(token: string): Record<string, string> {
    return token.startsWith("dmr_")
        ? { "X-Relay-Token": token }
        : { Authorization: `Bearer ${token}` }
}

/**
 * token: the credential for the next connect; a function is asked again
 * on every reconnect (an access token expires)
 */
export async function startRelayTunnel(
    relayUrl: string,
    token: string | (() => Promise<string>),
    localPort: number,
): Promise<RelayTunnel> {
    let headers: Record<string, string> = {}
    let tunnelId = ""
    let prefix = ""
    let stopped = false

    const connect = async () => {
        const credential = typeof token === "string" ? token : await token()
        const res = await fetch(`${relayUrl}/mcp-api/connect`, {
            method: "POST",
            headers: {
                ...relayAuthHeaders(credential),
                "Content-Type": "application/json",
            },
            // Asking for the old id keeps open tabs working after a relay
            // restart or a network break
            body: JSON.stringify({ resume: tunnelId || undefined }),
        })
        if (!res.ok) {
            throw new Error(
                `Relay refused the connection: ${res.status} ${await res.text()}`,
            )
        }
        const data = (await res.json()) as {
            tunnel: string
            secret: string
            prefix: string
        }
        if (prefix && data.prefix !== prefix) {
            log.warn(`Relay gave a new address; reopen the preview at ${relayUrl}${data.prefix}/shell/`)
        }
        tunnelId = data.tunnel
        prefix = data.prefix
        headers = { "X-Tunnel-Secret": data.secret }
    }

    await connect()
    log.info(`Relay tunnel open: ${relayUrl}${prefix}/`)

    const poll = async () => {
        while (!stopped) {
            try {
                const res = await fetch(
                    `${relayUrl}/mcp-api/t/${tunnelId}/next`,
                    { headers, signal: AbortSignal.timeout(POLL_TIMEOUT_MS) },
                )
                if (res.status === 204) continue
                if (res.status === 404) {
                    await connect()
                    continue
                }
                if (!res.ok) throw new Error(`poll: ${res.status}`)
                const request = (await res.json()) as TunnelRequest
                // Not awaited: the next poll starts while this one is served
                void answer(request)
            } catch (err) {
                if (stopped) return
                log.debug(`Relay poll failed, retrying: ${String(err)}`)
                await new Promise((r) => setTimeout(r, 2000))
            }
        }
    }

    const answer = async (request: TunnelRequest) => {
        let reply: {
            id: string
            status: number
            headers: Record<string, string>
            body: string
        }
        try {
            reply = { id: request.id, ...(await replay(request)) }
        } catch (err) {
            log.warn(`Relay request failed: ${String(err)}`)
            reply = { id: request.id, status: 502, headers: {}, body: "" }
        }
        try {
            await fetch(`${relayUrl}/mcp-api/t/${tunnelId}/reply`, {
                method: "POST",
                headers: { ...headers, "Content-Type": "application/json" },
                body: JSON.stringify(reply),
            })
        } catch (err) {
            log.debug(`Relay reply failed: ${String(err)}`)
        }
    }

    const replay = (request: TunnelRequest) =>
        new Promise<{
            status: number
            headers: Record<string, string>
            body: string
        }>((resolve, reject) => {
            const sent: Record<string, string> = {
                host: `localhost:${localPort}`,
                "x-relay-base": prefix,
            }
            for (const name of REQUEST_HEADERS) {
                const value = request.headers[name]
                if (typeof value === "string") sent[name] = value
            }
            const req = http.request(
                {
                    host: "127.0.0.1",
                    port: localPort,
                    method: request.method,
                    path: request.path,
                    headers: sent,
                },
                (res) => {
                    const chunks: Buffer[] = []
                    res.on("data", (c: Buffer) => chunks.push(c))
                    res.on("end", () => {
                        const out: Record<string, string> = {}
                        for (const [k, v] of Object.entries(res.headers)) {
                            if (typeof v === "string") out[k] = v
                        }
                        resolve({
                            status: res.statusCode ?? 502,
                            headers: out,
                            body: Buffer.concat(chunks).toString("base64"),
                        })
                    })
                    res.on("error", reject)
                },
            )
            req.on("error", reject)
            req.end(request.body ? Buffer.from(request.body, "base64") : undefined)
        })

    for (let i = 0; i < POLLERS; i++) void poll()

    return {
        origin: new URL(relayUrl).origin,
        get prefix() {
            return prefix
        },
        stop() {
            stopped = true
        },
    }
}
