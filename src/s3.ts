/**
 * This module contains signing logic that is specific for the S3
 * service, see [[signS3Request]].
 *
 * Additionally there's POST form parameter authentication,
 * which is designed mainly to allow users to upload files
 * to S3 directly from their browser. See [[signS3Policy]].
 */
/** */

import { URLSearchParams, URL } from 'url'

import { formatTimestamp, getSigning, signString, MAIN_ALGORITHM,
    RelaxedCredentials, GetSigningData, SignOptions } from './core'
import { hashBody, signRequest, SignHTTPOptions, CanonicalOptions, SignedRequest } from './http'
import { DEFAULT_REGION } from './util/endpoint'
import { getHeader } from './util/request'

export interface PolicySignOptions {
    timestamp?: string | Date
    getSigningData?: GetSigningData
}

export interface SignedS3Request extends SignedRequest {
    /** If set to true, the hash will be set to true */
    unsigned?: boolean
}

/** Maximum value for the X-Amz-Expires query parameter */
export const EXPIRES_MAX = 604800

/** Option defaults for the S3 service */
export const S3_OPTIONS = {
    dontNormalize: true,
    onlyEncodeOnce: true
}

/** Special value for payload digest, which indicates the payload is not signed */
export const PAYLOAD_UNSIGNED = 'UNSIGNED-PAYLOAD'

function patchURL(
    request: SignedS3Request,
    extra: {[key: string]: string},
    url: { host?: string, pathname?: string, searchParams?: URLSearchParams },
    set?: boolean
) {
    if (set || request.url !== url) {
        if (!url.searchParams) {
            url.searchParams = new URLSearchParams()
        }
    } else {
        const { host, pathname, searchParams } = url
        url = { host, pathname, searchParams: new URLSearchParams(searchParams) }
    }
    Object.keys(extra).forEach(k => url.searchParams!.append(k, extra[k]))
    return url
}

function patchHeaders(
    request: SignedS3Request,
    extra: {[key: string]: string},
    set?: boolean
) {
    const headers = set ?
        (request.headers = request.headers || {}) : { ...request.headers }
    Object.keys(extra).forEach(k => { headers[k] = extra[k] })
    return headers
}

/**
 * High-level function that signs an HTTP request for S3 using
 * `AWS-HMAC-SHA256` with either headers (`Authorization`) or query
 * parameters (presigned URL) depending on the `query` option.
 * 
 * This is a special version of [[signRequest]] that implements
 * some quirks needed for S3:
 * 
 *  - For header authorization, the `x-amz-content-sha256` is
 *    set to the body hash used to calculate the signature.
 *    Also, you can set `unsigned` in the request to set hash
 *    to `UNSIGNED_PAYLOAD`.
 *
 *  - For query authorization, the `X-Amz-Expires` parameter is
 *    set to `EXPIRES_MAX` if not present. The body hash is set to
 *    `UNSIGNED_PAYLOAD` (for S3, query authorization can't sign the body).
 *
 *  - `S3_OPTIONS` are applied by default (disables normalization
 *    and double encoding for pathname when calculating signature)
 *    and `serviceName` defaults to `s3` if host was not passed.
 *
 * The extra parameters are returned with the others, and also
 * set if requested.
 * 
 * @param credentials Credentials to sign the request with
 * @param request HTTP request to sign, see [[SignedS3Request]]
 * @param options Other options
 * @returns Authorization headers / query parameters
 */
export function signS3Request(
   credentials: RelaxedCredentials,
   request: SignedS3Request,
   options?: SignHTTPOptions & CanonicalOptions & SignOptions
): {[key: string]: string} {
    let { url, body, unsigned, headers } = request
    url = typeof url === 'string' ? new URL(url) : url
    const originalRequest = request
    const extra: {[key: string]: string} = {}

    if (options && options.query) {
        body = unsigned === false ? body : { hash: PAYLOAD_UNSIGNED }
        if (!(url.searchParams && url.searchParams.has('X-Amz-Expires'))) {
            extra['X-Amz-Expires'] = EXPIRES_MAX.toString()
            url = patchURL(request, extra, url, options && options.set)
        }
        request = { ...request, url, body }
    } else {
        const hash = unsigned ? PAYLOAD_UNSIGNED : hashBody(body, options)
        if (!getHeader(headers, 'x-amz-content-sha256')[1]) {
            extra['x-amz-content-sha256'] = hash
            headers = patchHeaders(request, extra, options && options.set)
        }
        request = { ...request, url, headers, body: { hash } }
    }

    if (typeof request.url !== 'string' && !request.url.host) {
        credentials = { serviceName: 's3', ...credentials }
    }
    const result = { ...extra, ...signRequest(
        credentials, request, { ...S3_OPTIONS, ...options }) }
    if (options && options.set && options.query &&
        typeof originalRequest.url === 'string') {
        originalRequest.url = (url as URL).toString()
    }
    if (typeof originalRequest.url !== 'string' && !originalRequest.url.host) {
        originalRequest.url.host = url.host
    }
    return result
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
 * > For a working example of use, see `demo_s3_post`.
 *
 * [create-form]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
 * [construct-policy]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
 * [policy-auth]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html
 *
 * @param credentials The IAM credentials to use for signing
 *                   (service name defaults to 's3', and the default region)
 * @param policy The policy object
 * @param timestamp You can optionally provide the timestamp for signing,
 *                  otherwise it will be generated using [[formatTimestamp]]
 * @returns Key - value object containing the form parameters
 */
export function signS3Policy(
    credentials: RelaxedCredentials,
    policy: any,
    options?: PolicySignOptions
): {[key: string]: string} {
    const ts = options && options.timestamp
    const cr = { serviceName: 's3', regionName: DEFAULT_REGION, ...credentials }

    // Get timestamp, derive key, prepare form fields
    const timestamp = (typeof ts === 'string') ? ts : formatTimestamp(ts)
    const { signing, credential } = getSigning(timestamp, cr, options)
    const fields: {[key: string]: string} = {
        'x-amz-date': timestamp,
        'x-amz-algorithm': MAIN_ALGORITHM,
        'x-amz-credential': credential,
    }

    // Add the fields to the policy conditions
    const conditions = (policy.conditions || []).concat(
        Object.keys(fields).map(k => ({ [k]: fields[k] })))
    const finalPolicy = JSON.stringify({ ...policy, conditions })

    // Encode and sign the policy
    const encodedPolicy = Buffer.from(finalPolicy).toString('base64')
    const signature = signString(signing.key, encodedPolicy).toString('hex')

    return { ...fields, 'policy': encodedPolicy, 'x-amz-signature': signature }
}

import * as chunked from './s3_chunked'
export { chunked }
