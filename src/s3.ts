/**
 * This module contains signing logic that is specific for the S3 service.
 *
 *  - `Authorization`-based signing: The process is the same as for any
 *    other HTTP request, but path normalization & double encoding must be
 *    disabled and the `x-amz-content-sha256` header must be present.  
 *    **See {{signRequestHeader}} and {{autoSignRequestHeader}}**.
 *
 *  - Query-based signing (presigned URLs): the process is the same as
 *    above, except that instead of headers, query parameters are added
 *    to sign the request.  
 *    **See {{signRequestQuery}}, {{autoSignRequestQuery}} and {{signURL}}.**
 *
 *  - Additionally there's POST form parameter authentication,
 *    which is designed mainly to allow users to upload files
 *    to S3 directly from their browser.  
 *    **See {{signPolicy}}.**
 */

import { RequestOptions } from 'http'
import { URLSearchParams, URL } from 'url'
import { createHash } from 'crypto'

import { formatTimestamp, getSigningData, signString, sign, MAIN_ALGORITHM,
    RelaxedCredentials, Credentials, GetSigningData, SignOptions, signDigest } from './core'
import { getCanonical, signRequest, autoSignRequest, SignHTTPOptions, CanonicalOptions, getCanonicalHeaders } from './http'
import { DEFAULT_REGION, parseHost } from './util/endpoint'

export interface PolicySignOptions {
    timestamp?: string | Date
    getSigningData?: GetSigningData
}

/** Maximum value for the X-Amz-Expires query parameter */
export const EXPIRES_MAX = 604800

export const S3_OPTIONS = {
    dontNormalize: true,
    onlyEncodeOnce: true
}

export const PAYLOAD_UNSIGNED = 'UNSIGNED-PAYLOAD'
export const PAYLOAD_STREAMING = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'

const EMPTY_HASH = createHash('sha256').digest('hex')

function hashBody(body?: false | string | Buffer | { hash: string }) {
    if (body === false) {
        return PAYLOAD_UNSIGNED
    }
    if (!body) {
        return EMPTY_HASH
    }
    return (typeof (body as any).hash === 'string') ? (body as any).hash
        : createHash('sha256').update(body as any).digest('hex')
}

/**
 * Calls {{signRequest}} setting the correct options for S3,
 * and adds an `x-amz-content-sha256` header.
 *
 * Pass `false` as body to create an unsigned payload signature.
 */
export function signRequestHeader(
    credentials: Credentials,
    method: string,
    url: string | {
        host?: string
        pathname: string
        searchParams: URLSearchParams | string | {[key: string]: string}
    },
    headers: {[key: string]: string | string[]},
    body?: false | string | Buffer | { hash: string },
    options?: SignHTTPOptions & CanonicalOptions & SignOptions
) {
    const hash = hashBody(body)
    const newHeaders = { 'x-amz-content-sha256': hash }
    const authHeaders = signRequest(credentials, method, url,
        { ...headers, ...newHeaders }, { hash }, { ...S3_OPTIONS, ...options })
    return { ...newHeaders, ...authHeaders }
}

/**
 * Calls {{autoSignRequest}} setting the correct options for S3,
 * and adds an `x-amz-content-sha256` header.
 *
 * Pass `false` as body to create an unsigned payload signature.
 */
export function autoSignRequestHeader(
    credentials: RelaxedCredentials,
    request: RequestOptions,
    body?: false | string | Buffer | { hash: string },
    options?: SignHTTPOptions & CanonicalOptions & SignOptions
) {
    const hash = hashBody(body)
    const newHeaders = { 'x-amz-content-sha256': hash }
    request = {...request, headers: { ...request.headers, ...newHeaders } }
    const authHeaders = autoSignRequest(credentials, request,
        { hash }, { ...S3_OPTIONS, ...options })
    return { ...newHeaders, ...authHeaders }
}

export function signRequestHeaderChunked() {

}

/**
 * High-level function that signs an HTTP request using
 * `AWS-HMAC-SHA256` but using query parameters (i.e. presigned
 * URL) instead of headers.
 * 
 * The usage and behaviour is the same as for {{signRequest}}, except:
 * 
 *  - Instead of looking for an `X-Amz-Date` header, it looks
 *    for a query parameter of that name.
 *  - Instead of returning headers (such as `Authorization`),
 *    it returns parameters to add to the query. `X-Aws-Expires`
 *    is set to EXPIRES_MAX if not present.
 *  - It uses different option defaults (for S3) and there's
 *    no `body` parameter (payload can't be signed through query).
 *
 * @param credentials Credentials to sign the request with
 * @param method HTTP method
 * @param url An object containing the pathname and the query string,
 *            and optionally the hostname (if a string is passed,
 *            it will be parsed using `url.URL`)
 * @param headers HTTP headers to sign
 * @param options Other options
 * @returns Object with query parameters to add to the URL
 */
export function signRequestQuery(
    credentials: Credentials,
    method: string,
    url: string | {
        host?: string
        pathname: string
        searchParams: URLSearchParams | string | {[key: string]: string}
    },
    headers: {[key: string]: string | string[]},
    options?: SignHTTPOptions & CanonicalOptions & SignOptions
) {
    options = { ...S3_OPTIONS, ...options }
    const joined = (value: string | string[]) =>
        (typeof value === 'string') ? value : value.join(', ')
    const normHeaders = new Map(
        Object.keys(headers).map(x => [ x.toLowerCase(), joined(headers[x]) ]))
    const parsedUrl = typeof url === 'string' ? new URL(url) : url
    const query = new URLSearchParams(parsedUrl.searchParams)
    const newQuery: {[key: string]: string} = {}

    // Populate host header if necessary
    let host = normHeaders.get('host') || normHeaders.get(':authority')
    if (!host) {
        if (!parsedUrl.host) {
            throw new Error('No host provided on headers nor URL')
        }
        host = parsedUrl.host
        headers = { ...headers, host }
    }

    // Populate & validate timestamp parameter
    let timestamp = (options || {}).timestamp || query.get('X-Amz-Date')
    if (timestamp) {
        if (!/\d{8}T\d{6}Z/.test(timestamp)) {
            throw new Error(`Invalid timestamp provided: ${timestamp}`)
        }
    } else {
        timestamp = newQuery['X-Amz-Date'] = formatTimestamp()
    }

    // Derive key and set parameters
    const { accessKey, secretKey, regionName, serviceName } = credentials
    const derive = (options && options.getSigningData) || getSigningData
    const signing = derive(timestamp, secretKey,
        regionName || DEFAULT_REGION, serviceName || 's3')
    newQuery['X-Amz-Algorithm'] = MAIN_ALGORITHM
    newQuery['X-Amz-Credential'] = `${accessKey}/${signing.scope}`

    // Set other needed parameters
    newQuery['X-Amz-SignedHeaders'] = getCanonicalHeaders(headers)[1]
    if (!query.has('X-Amz-Expires')) {
        newQuery['X-Amz-Expires'] = EXPIRES_MAX.toString()
    }

    // Build canonical string, get digest, calculate signature
    Object.keys(newQuery).forEach(k => query.append(k, newQuery[k]))
    const { canonical } = getCanonical(
        method, parsedUrl.pathname, query, headers, PAYLOAD_UNSIGNED, options)
    const digest = createHash('sha256').update(canonical).digest('hex')
    const signature = signDigest(MAIN_ALGORITHM, digest, timestamp, signing)

    newQuery['X-Amz-Signature'] = signature.toString('hex')
    return newQuery
}

/**
 * Convenience function to presign a URL using {{signRequestQuery}}.
 * 
 * @param credentials Credentials to sign the request with
 * @param url URL to sign
 * @param options Other options
 */
export function signURL(
    credentials: RelaxedCredentials,
    url: string | URL,
    options?: {
        method?: string,
        headers?: {[key: string]: string | string[]},
    } & SignHTTPOptions & CanonicalOptions & SignOptions
) {
    options = options || {}
    url = (typeof url === 'string') ? new URL(url) : url
    if (!url.host) {
        throw new Error('URL to sign needs to have a hostname')
    }
    if (!credentials.serviceName || !credentials.regionName) {
        credentials = { ...parseHost(url.host), ...credentials }
    }
    const query = new URLSearchParams(url.searchParams)
    const newQuery = signRequestQuery(credentials as Credentials,
        options.method || 'GET', url, options.headers || {}, options)
    Object.keys(newQuery).forEach(k => query.append(k, newQuery[k]))
    url.search = query.toString()
    return url.toString()
}

/**
 * (POST form param based authentication)
 *
 * This method signs the passed policy and returns the
 * [authentication parameters][policy-auth] that you need to attach
 * to the [created form][create-form].
 *
 * See [this][construct-policy] for how to write the policy.
 * The policy shouldn't contain any authentication parameters (such
 * as `x-amz-date`); these will be added before signing it.
 *
 * @param credentials The IAM credentials to use for signing
 *                   (service name defaults to 's3', and the default region)
 * @param policy The policy object
 * @param timestamp You can optionally provide the timestamp for signing,
 *                  otherwise it will be generated using {{formatTimestamp}}
 * @returns Key - value object containing the form parameters
 *
 * [create-form]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
 * [construct-policy]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
 * [policy-auth]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html
 */
export function signPolicy(
    credentials: RelaxedCredentials,
    policy: any,
    options?: PolicySignOptions
): {[key: string]: string} {
    const { accessKey, secretKey, regionName, serviceName } = credentials
    const derive = (options && options.getSigningData) || getSigningData
    const ts = options && options.timestamp

    // Get timestamp, derive key, prepare form fields
    const timestamp = (typeof ts === 'string') ? ts : formatTimestamp(ts)
    const { key, scope } = derive(timestamp, secretKey,
        regionName || DEFAULT_REGION, serviceName || 's3')
    const fields: {[key: string]: string} = {
        'x-amz-date': timestamp,
        'x-amz-algorithm': MAIN_ALGORITHM,
        'x-amz-credential': `${accessKey}/${scope}`,
    }

    // Add the fields to the policy conditions
    const conditions = (policy.conditions || []).concat(
        Object.keys(fields).map(k => ({ [k]: fields[k] })))
    const finalPolicy = JSON.stringify({ ...policy, conditions })

    // Encode and sign the policy
    const encodedPolicy = Buffer.from(finalPolicy).toString('base64')
    const signature = signString(key, encodedPolicy).toString('hex')

    return { ...fields, 'policy': encodedPolicy, 'x-amz-signature': signature }
}
