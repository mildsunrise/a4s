/**
 * This module implements the signing logic for an event stream.
 * The main method is [[signEvent]] which offers a similar API to [[signRequest]].
 *
 * The mechanics of a signed event stream are pretty similar to `s3_chunked`,
 * each chunk (now an 'event') is prepended a signature which depends on the
 * previous signature. However, here each chunk can have different timestamps.
 *
 * @module
 */

import { formatTimestamp, Credentials, SignOptions, signChunk, getSigning, SigningData } from './core'
import { hashBody } from './http'
import { encodeHeaders, HeaderArray, HeaderObject } from './events'

export interface SignEventOptions {
    /**
     * Add the returned parameters to the passed headers (or searchParams,
     * if query signing was requested)
     */
    set?: boolean
}

/**
 * Returned by [[signEvent]]. Contains the generated authorization headers
 * (`headers`) and other information (signature itself, derived key and
 * timestamp).
 */
export interface SignResult {
    /** Authorization parameters */
    params: HeaderObject
    /** Signing timestamp */
    timestamp: string
    /** Derived signing data */
    signing: SigningData
    /** Generated binary signature */
    signature: Buffer
}

/** Special value for payload digest, which indicates payload streaming encoding */
export const PAYLOAD_EVENT = 'STREAMING-AWS4-HMAC-SHA256-EVENTS'

/** Algorithm used for the event signatures in event stream encoding */
export const ALGORITHM_EVENT = 'AWS4-HMAC-SHA256-PAYLOAD'

const getHeadersDigest = (headers: HeaderObject) =>
    hashBody(encodeHeaders(Object.keys(headers).sort()
        .map(k => [k, headers[k]]) as HeaderArray))

/**
 * Sign an event, and return the generated authorization headers.
 * If the `set` option is active, they will be added to `headers` too.
 * 
 * If the `:date` header isn't set to a `timestamp`, it'll be populated
 * and returned along with the other headers.
 * 
 * Note: Unlike HTTP headers, event headers are case-sensitive.
 * 
 * @param lastSignature The last signature, hex-encoded. If this is the first
 *     event, pass the initial request signature (seed signature).
 * @param credentials Credentials to derive key from
 * @param headers Event headers, as an array or an object
 * @param chunk Event payload to calculate hash of (alternatively you may
 *              calculate it yourself and pass it as `{ hash: '<hex>' }`)
 * @param options Signing options
 * @returns Object containing the authorization headers to add to the request
 * in `params`, and some additional info.
 */
export function signEvent(
    lastSignature: string,
    credentials: Credentials,
    headers: HeaderObject,
    chunk?: Buffer | { hash: string },
    options?: SignEventOptions & SignOptions
): SignResult {
    const params: HeaderObject = {}

    // Populate :date if needed
    let date: Date
    if (headers[':date'] && headers[':date'].type === 'timestamp') {
        date = headers[':date'].data
    } else {
        date = new Date()
        params[':date'] = { type: 'timestamp', data: date }
    }

    // Calculate & populate signature
    const timestamp = formatTimestamp(date)
    const { signing } = getSigning(timestamp, credentials, options)
    const signature = signChunk(lastSignature,
        getHeadersDigest({ ...headers, ...params }), hashBody(chunk),
        timestamp, signing)
    params[':chunk-signature'] = { type: 'buffer', data: signature }

    // Set parameters if requested
    if (options && options.set) {
        Object.keys(params).forEach(k => { headers[k] = params[k] })
    }
    return { params, signature, signing, timestamp }
}
