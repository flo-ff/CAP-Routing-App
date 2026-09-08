const cds = require('@sap/cds')
const http = require('node:http')
const https = require('node:https')
const { buildHeadersForDestination, getDestination } = require('@sap-cloud-sdk/connectivity')

const LOG = cds.log('mcp')

// Hop-by-hop headers must not be forwarded (RFC 7230 §6.1).
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

// Request headers we deliberately do NOT forward to the backend.
// The user's IAS bearer must never be forwarded to the backend. It is replaced
// below by the authentication configured on the resolved BTP destination
// (Basic, principal propagation, OAuth, etc.).
const DROP_REQUEST_HEADERS = new Set([
  'authorization',
  'host',
  'content-length',
  'connection',
  'x-dev-email',
])

/**
 * Normalise the Cloud SDK proxy headers into a plain object.
 * Newer @sap-cloud-sdk/connectivity returns `headers` as a plain object
 * (Record<string, string>); older versions returned an array of {key, value}.
 * Handle both so principal-propagation / proxy-auth headers are forwarded.
 */
function proxyHeaders(proxyConfiguration) {
  const h = proxyConfiguration?.headers
  if (!h) return {}
  if (Array.isArray(h)) {
    const out = {}
    for (const item of h) out[item.key] = item.value
    return out
  }
  return { ...h }
}

function filterRequestHeaders(reqHeaders) {
  const out = {}
  for (const [k, v] of Object.entries(reqHeaders)) {
    if (DROP_REQUEST_HEADERS.has(k.toLowerCase())) continue
    out[k] = v
  }
  return out
}

function buildTargetUrl(destinationUrl, backendPath, requestPath) {
  const base = destinationUrl.replace(/\/+$/, '')
  const backend = backendPath || ''
  const request = requestPath || ''
  let path

  if (!backend || backend === '/') path = request
  else if (!request || request === '/') path = backend
  else path = `${backend.replace(/\/+$/, '')}/${request.replace(/^\/+/, '')}`

  if (path && !path.startsWith('/')) path = `/${path}`
  return new URL(base + (path || '/'))
}

/**
 * Resolve the Cloud Connector Location ID to use for a request.
 *
 * The resolved route's `locationId` is authoritative — `normalizeRoute` in
 * `lib/routes.js` already folds the top-level `cds.mcp.locationId` default into
 * it. It is honoured even when it is an explicit empty string: a destination
 * whose Cloud Connector is registered under the default (empty) location must
 * send NO `SAP-Connectivity-SCC-Location_ID` header, and must NOT silently
 * inherit another route's location id. Only when the route carries no
 * `locationId` at all (undefined/null — e.g. the legacy single-route fallback)
 * do we look at env vars and then the destination's own configured location.
 *
 * Returns '' when nothing is configured, so the caller simply omits the header.
 */
function resolveLocationId(route, mcp, destination) {
  if (route && route.locationId != null) return route.locationId
  return (
    (mcp && mcp.locationId) ||
    process.env.CDS_MCP_LOCATIONID ||
    destination?.cloudConnectorLocationId ||
    destination?.originalProperties?.CloudConnectorLocationId ||
    destination?.originalProperties?.['CloudConnectorLocationId'] ||
    ''
  )
}

/**
 * Resolve the OnPremise destination (with the user JWT for principal
 * propagation) and stream the MCP request through the connectivity proxy to the
 * on-prem ABAP MCP server, piping the response (including SSE) straight back.
 */
async function proxyToBackend(req, res) {
  const started = Date.now()
  const mcp = cds.env.mcp || {}
  const route = req.mcpRoute || {}
  // Per-route config (multi-route), falling back to the flat cds.mcp defaults so
  // a single-route/legacy setup keeps working unchanged.
  const destinationName = route.destination || mcp.destination
  const backendPath = route.backendPath != null ? route.backendPath : mcp.backendPath
  const timeout = route.timeout || mcp.timeout
  const cid = req.correlationId
  const mcpMethod = req.parsedMcpMethod // set by the router when a body is buffered (optional)

  // IAS client_credentials tokens carry no user (no email/user_uuid) and must not
  // be used as subscriber-JWT for OnPremise BasicAuth — they trigger
  // `serviceToken('destination'/'connectivity', {jwt: CC_JWT})` with a mismatched
  // tenant (zid/app_tid) -> "Failed to fetch subscriber service token" +
  // "Failed to add proxy authorization header - client credentials grant failed!".
  // For non-user auth (BasicAuth / OAuth2ClientCredentials) use the provider
  // token (no JWT) instead.
  function isClientCredentialsToken(jwt) {
    if (!jwt || typeof jwt !== 'string') return false
    try {
      const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'))
      return payload.grant_type === 'client_credentials' || (!payload.email && !payload.mail && !payload.user_uuid && !payload.user_name && !!payload.client_id)
    } catch {
      return false
    }
  }

  const isCC = isClientCredentialsToken(req.jwt)
  if (isCC) {
    LOG.info('client_credentials grant detected — will use provider destination flow (no subscriber JWT)', { correlationId: cid })
  }

  let destination
  try {
    // For CC + BasicAuth the subscriber flow always fails; try provider flow first.
    // For user flows keep the JWT so PrincipalPropagation / user-dependent destinations work.
    const jwtForDestination = isCC ? undefined : req.jwt
    destination = await getDestination({ destinationName, jwt: jwtForDestination })
    if (!destination) throw new Error(`Destination '${destinationName}' not found`)
  } catch (err) {
    const msg = err.message || ''
    const isProxyAuthFailure = msg.includes('Failed to add proxy authorization header') || msg.includes('Failed to fetch subscriber service token')
    // Fallback: if we tried with a user JWT and got a proxy-auth failure due to CC, retry as provider flow.
    if (!isCC && isProxyAuthFailure && req.jwt) {
      LOG.warn('destination resolution with subscriber JWT failed, retrying as provider flow', { correlationId: cid, error: msg })
      try {
        destination = await getDestination({ destinationName })
        if (!destination) throw new Error(`Destination '${destinationName}' not found`)
        LOG.info('provider-flow retry succeeded', { correlationId: cid })
      } catch (retryErr) {
        LOG.error('destination resolution failed', {
          correlationId: cid,
          destination: destinationName,
          error: retryErr.message,
          cause: err.stack,
        })
        return sendError(res, 502, 'destination_error', retryErr.message)
      }
    } else {
      LOG.error('destination resolution failed', {
        correlationId: cid,
        destination: destinationName,
        error: err.message,
        stack: err.stack,
        cause: err.cause?.message,
      })
      return sendError(res, 502, 'destination_error', err.message)
    }
  }

  if (isCC && destination.authentication === 'PrincipalPropagation') {
    LOG.error('client_credentials not compatible with PrincipalPropagation destination', {
      correlationId: cid,
      destination: destinationName,
    })
    return sendError(
      res,
      502,
      'destination_error',
      `Destination '${destinationName}' uses PrincipalPropagation which requires a user token (authorization_code). Use a BasicAuthentication/OAuth2ClientCredentials destination for client_credentials.`,
    )
  }

  let destinationHeaders
  try {
    destinationHeaders = await buildHeadersForDestination(destination)
  } catch (err) {
    LOG.error('destination authentication failed', {
      correlationId: cid,
      destination: destinationName,
      authentication: destination.authentication,
      error: err.message,
    })
    return sendError(res, 502, 'destination_authentication_error', err.message)
  }

  // Build the absolute backend target URL. Anything after the /mcp mount point
  // is appended, and the destination's sap-client is added as a query param.
  const subPath = req.url && req.url !== '/' ? req.url : ''
  const target = buildTargetUrl(destination.url, backendPath, subPath)
  const sapClient = destination.sapClient || destination.originalProperties?.['sap-client']
  if (sapClient && !target.searchParams.has('sap-client')) {
    target.searchParams.set('sap-client', sapClient)
  }

  const isOnPremise = destination.proxyType === 'OnPremise'
  const proxy = destination.proxyConfiguration
  if (isOnPremise && !proxy) {
    return sendError(res, 502, 'connectivity_error', 'OnPremise destination without connectivity proxy — is the connectivity service bound?')
  }

  const headers = {
    ...filterRequestHeaders(req.headers),
    ...destinationHeaders,
    host: target.host,
    'x-correlation-id': cid,
    ...(isOnPremise ? proxyHeaders(proxy) : {}),
  }

  // SCC tunnel selection: the connectivity proxy must be told the Cloud
  // Connector Location ID, otherwise it looks for an SCC registered under the
  // default (empty) location and fails when the real SCC uses a named location.
  // See resolveLocationId — an explicit empty string is honoured as "default
  // (empty) location" and is not overridden by the global default.
  const locationId = resolveLocationId(route, mcp, destination)
  const LOC_HEADER = 'SAP-Connectivity-SCC-Location_ID'
  const hasLoc = Object.keys(headers).some((k) => k.toLowerCase() === LOC_HEADER.toLowerCase())
  if (isOnPremise && locationId && !hasLoc) headers[LOC_HEADER] = locationId
  // Only warn when nothing was configured anywhere — an explicit empty
  // locationId on the route is intentional (SCC under the default location).
  if (isOnPremise && !locationId && (route.locationId == null)) {
    LOG.warn('no SCC location id resolved — connectivity proxy may not match a tunnel', {
      correlationId: cid,
      destination: destinationName,
    })
  }

  // When the router buffered the body (to log the MCP method), send it with an
  // accurate Content-Length instead of streaming.
  if (Buffer.isBuffer(req.rawBody)) {
    headers['content-length'] = Buffer.byteLength(req.rawBody)
  }

  // For an OnPremise destination we talk to the connectivity proxy in
  // forward-proxy mode (absolute request URI). For an internet destination we
  // connect directly to the target host.
  const useProxy = isOnPremise && proxy
  const agentModule = (useProxy ? proxy.protocol : target.protocol) === 'https:' ? https : http
  const options = useProxy
    ? { host: proxy.host, port: proxy.port, method: req.method, path: target.toString(), headers }
    : {
        host: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        method: req.method,
        path: target.pathname + target.search,
        headers,
      }

  LOG.info('mcp request → backend', {
    correlationId: cid,
    route: route.path,
    method: req.method,
    mcpMethod,
    user: req.principal?.email,
    destination: destinationName,
    authentication: destination.authentication,
    proxyType: destination.proxyType,
    target: `${target.origin}${target.pathname}`,
    locationId: headers[LOC_HEADER],
    sessionId: req.headers['mcp-session-id'],
  })

  const upstream = agentModule.request(options, (backendRes) => {
    const outHeaders = {}
    for (const [k, v] of Object.entries(backendRes.headers)) {
      if (!HOP_BY_HOP.has(k.toLowerCase())) outHeaders[k] = v
    }
    res.writeHead(backendRes.statusCode || 502, outHeaders)
    if (typeof res.flushHeaders === 'function') res.flushHeaders() // start SSE immediately

    backendRes.on('end', () => {
      LOG.info('mcp response ← backend', {
        correlationId: cid,
        status: backendRes.statusCode,
        contentType: backendRes.headers['content-type'],
        durationMs: Date.now() - started,
        user: req.principal?.email,
      })
    })
    backendRes.pipe(res)
  })

  // SSE streams are long-lived: only apply the timeout to non-streaming calls.
  const wantsStream = /text\/event-stream/i.test(req.headers['accept'] || '')
  if (!wantsStream && timeout) upstream.setTimeout(timeout, () => upstream.destroy(new Error('backend timeout')))

  upstream.on('error', (err) => {
    LOG.error('backend request error', {
      correlationId: cid,
      error: err.message,
      durationMs: Date.now() - started,
    })
    if (!res.headersSent) sendError(res, 502, 'backend_error', err.message)
    else res.end()
  })

  // Tear down the upstream connection if the client goes away.
  res.on('close', () => upstream.destroy())

  if (Buffer.isBuffer(req.rawBody)) upstream.end(req.rawBody)
  else req.pipe(upstream)
}

function sendError(res, status, error, detail) {
  res.status(status)
  res.json({ error, detail })
}

module.exports = { buildTargetUrl, resolveLocationId, proxyToBackend }
