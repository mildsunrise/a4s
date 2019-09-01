/**
 * Code for signing HTTP requests through Authorization header.
 * This module calculates the canonical request (and its digest
 * for signing), and also builds the resulting `Authorization`
 * header. It also provides high-level methods that do the whole
 * process.
 * 
 * See `signing` module for the actual signing logic.
 */

import { URL, URLSearchParams, parse } from 'url'
import { unescape } from 'querystring'
import { createHash } from 'crypto'
import { RequestOptions } from 'http'

import { formatTimestamp, sign, RelaxedCredentials, Credentials, MAIN_ALGORITHM, SignOptions } from './core'
import { parseHost, formatHost, DEFAULT_REGION } from './util/endpoint'

interface CanonicalOptions {
    dontNormalize?: boolean
    onlyEncodeOnce?: boolean
}

function escape(str: string) {
    const digits = '0123456789ABCDEF'
    const at = (a: any, x: any, b: any) => (a <= x && x <= b)
    return Array.from(Buffer.from(str)).map(x =>
        (at(0x61, x|0x20, 0x7A) || at(0x30, x, 0x39) || x===0x2D || x===0x2E || x===0x5F || x === 0x7E) ?
            String.fromCharCode(x) : `%${digits[x >> 4]}${digits[x & 0xF]}`
    ).join('')
}

/** Get canonical URL string (low-level) */
export function getCanonicalURI(pathName: string, options?: CanonicalOptions) {
    let parts = pathName.split('/').map(unescape)
    if (!(options && options.dontNormalize)) {
        const newParts: string[] = []
        let endingSlash = true
        for (const part of parts) {
            endingSlash = true
            if (part === '..') {
                newParts.pop()
            } else if (!(part === '' || part === '.')) {
                endingSlash = false
                newParts.push(part)
            }
        }
        parts = [''].concat(newParts).concat(endingSlash ? [''] : [])
    }
    parts = parts.map(escape)
    if (!(options && options.onlyEncodeOnce)) {
        parts = parts.map(escape)
    }
    return parts.join('/')
}

/** Get canonical query string (low-level) */
export function getCanonicalQuery(query: URLSearchParams | string | {[key: string]: string}) {
    const pquery = query instanceof URLSearchParams ?
        query : new URLSearchParams(query)
    const parts: string[] = []
    // .sort() uses UTF-16 code units instead of codepoints... close enough
    for (const key of Array.from(new Set(pquery.keys())).sort()) {
        if (!key) {
            return // FIXME: verify that services need empty keys stripped
        }
        const pkey = escape(key) + '='
        for (const value of pquery.getAll(key).sort()) {
            parts.push(pkey + escape(value))
        }
    }
    return parts.join('&')
}

/** Get canonical headers and signed header strings (low-level) */
export function getCanonicalHeaders(headers: {[key: string]: string | string[]}) {
    const trim = (x: string) => x.trim().replace(/\s+/g, ' ')
    const normalized = new Map<string, string[]>()
    for (const key of Object.keys(headers)) {
        const name = trim(key).toLowerCase()
        const value = headers[key]
        const values = typeof value === 'string' ? [value] : value
        normalized.set(name, (normalized.get(name) || []).concat(values.map(trim)))
    }
    const signedHeaders = Array.from(normalized.keys()).sort()
    const canonicalHeaders = signedHeaders.map(k =>
        `${k}:${normalized.get(k)!.join(',')}\n`).join('')
    return [ canonicalHeaders, signedHeaders.join(';') ]
}

/**
 * Function to generate a canonical request string.
 * Most users won't need to call this directly.
 *
 * **Important:** It's mandatory for 'Host' (HTTP/1.1) or ':authority' (HTTP/2) to
 * be present in `headers`. 
 * 
 * @param method HTTP method
 * @param pathName URL pathname (i.e. without query string)
 * @param query Query parameters (if a string or object is provided, it will be parsed with `URLSearchParams`)
 * @param headers HTTP headers to include in the canonical request.
 * @param body Hash of the request's body, hex-encoded.
 * @param options Other options
 * @returns An object containing `canonical` (the canonical request),
 *          and the `signedHeaders` string.
 */
export function getCanonical(
    method: string,
    pathName: string,
    query: URLSearchParams | string | {[key: string]: string},
    headers: {[key: string]: string | string[]},
    bodyHash: string,
    options?: CanonicalOptions
) {
    const [ canonicalHeaders, signedHeaders ] = getCanonicalHeaders(headers)
    const canonical = [
        method.toUpperCase().trim(),
        getCanonicalURI(pathName, options),
        getCanonicalQuery(query),
        canonicalHeaders,
        signedHeaders,
        bodyHash,
    ].join('\n')
    return { canonical, signedHeaders }
}

/**
 * Method to construct the value of the `Authorization`
 * header from its data.
 */
export function buildAuthorization(data: {
    algorithm: string
    signature: Buffer
    credential: string
    signedHeaders: string
}) {
    const fields = [
        `Credential=${data.credential}`,
        `SignedHeaders=${data.signedHeaders}`,
        `Signature=${data.signature.toString('hex')}`,
    ]
    return `${data.algorithm} ${fields.join(', ')}`
}

/**
 * High-level function that signs an HTTP request using
 * `AWS-HMAC-SHA256` by generating an `Authorization` header.
 * 
 * This uses {{getCanonical}} to generate the canonical string,
 * obtains its digest, calculates the signature using `signing.sign()`
 * and constructs the header with {{buildAuthorization}}.
 * 
 * The method returns an object containing headers to be added to
 * the request. It contains at least the `Authorization` header, and:
 * 
 *  - If no `Host` or `:authority` header is present, a `Host` header
 *    is added based on `url` host. If neither was given, an error
 *    is thrown.
 *  - If no `X-Amz-Date` header is present, one is generated with
 *    {{formatTimestamp}}.
 * 
 * The format of the `x-amz-date` header is verified, and its
 * timestamp is used for signing.
 *
 * @param credentials Credentials to sign the request with
 * @param method HTTP method
 * @param url An object containing the pathname and the query string,
 *            and optionally the hostname (if a string is passed,
 *            it will be parsed using `url.URL`)
 * @param headers HTTP headers to sign
 * @param body Request body to calculate hash of (alternatively you may
 *             calculate it yourself and pass it as `{ hash: '<hex>' }`)
 * @param options Other options
 * @returns Object with headers to add to the request
 */
export function signRequest(
    credentials: Credentials,
    method: string,
    url: string | {
        host?: string
        pathname: string
        searchParams: URLSearchParams | string | {[key: string]: string}
    },
    headers: {[key: string]: string | string[]},
    body?: string | Buffer | { hash: string },
    options?: CanonicalOptions & SignOptions
) {
    const joined = (value: string | string[]) =>
        (typeof value === 'string') ? value : value.join(', ')
    const normHeaders = new Map(
        Object.keys(headers).map(x => [ x.toLowerCase(), joined(headers[x]) ]))
    const parsedUrl = typeof url === 'string' ? new URL(url) : url
    const newHeaders: {[key: string]: string} = {}

    // Populate host header if necessary
    let host = normHeaders.get('host') || normHeaders.get(':authority')
    if (!host) {
        if (!parsedUrl.host) {
            throw new Error('No host provided on headers nor URL')
        }
        host = newHeaders['host'] = parsedUrl.host
    }

    // Populate & validate timestamp header
    let timestamp = normHeaders.get('x-amz-date')
    if (timestamp) {
        if (!/\d{8}T\d{6}Z/.test(timestamp)) {
            throw new Error(`Invalid timestamp provided: ${timestamp}`)
        }
    } else {
        timestamp = newHeaders['x-amz-date'] = formatTimestamp()
    }

    // Obtain body hash
    let bodyHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    if (body) {
        bodyHash = (typeof (body as any).hash === 'string') ? (body as any).hash
            : createHash('sha256').update(body as any).digest('hex')
    }

    // Build canonical string, get digest, calculate signature
    const { canonical, signedHeaders } = getCanonical(
        method, parsedUrl.pathname, parsedUrl.searchParams,
        {...headers, ...newHeaders}, bodyHash, options)
    const digest = createHash('sha256').update(canonical).digest('hex')
    const { signature, credential } =
        sign(credentials, MAIN_ALGORITHM, digest, timestamp, options)

    // Generate Authorization header
    newHeaders['authorization'] = buildAuthorization(
        { algorithm: MAIN_ALGORITHM, signature, signedHeaders, credential })
    return newHeaders
}

/**
 * Convenience method that calls {{signRequest}} and replaces
 * `request.headers` with the merged headers.
 *
 * If you don't supply region and service name, they will
 * be extracted from `request.hostname` or `request.host`.
 *
 * Or, if you don't provide a hostname, it will be populated from
 * the `serviceName` (and `regionName` if present).
 *
 * @returns The passed request options object
 */
export function autoSignRequest(
    credentials: RelaxedCredentials,
    request: RequestOptions,
    body?: string | Buffer | { hash: string },
    options?: CanonicalOptions & SignOptions
) {
    const path = request.path || '/'
    let pathSep = path.indexOf('?')
    pathSep = (pathSep === -1) ? path.length : pathSep
    const pathname = path.substr(0, pathSep)
    const searchParams = path.substr(pathSep)

    let host = request.hostname || request.host
    if (!host) {
        if (!credentials.serviceName) {
            throw new Error('Neither hostname nor serviceName passed')
        }
        host = request.hostname = formatHost(credentials.serviceName, credentials.regionName, request.port)
        credentials.regionName = credentials.regionName || DEFAULT_REGION
    } else if (!credentials.regionName || !credentials.serviceName) {
        credentials = {...parseHost(host), ...credentials}
    }

    const headers: {[key: string]: string | string[]} = {}
    for (const key of Object.keys(request.headers || {})) {
        const value = request.headers![key]
        if (typeof value === 'string' || value instanceof Array) {
            headers[key] = value
        } else {
            headers[key] = '' + value
        }
    }

    const newHeaders = signRequest(credentials as Credentials,
        request.method || 'GET', { host, pathname, searchParams },
        headers, body, options)
    request.headers = {...request.headers, ...newHeaders}
    return request
}
