/**
 * Code for signing generic messages using AWS Signature version 4.
 * 
 * This module contains only common signing logic (i.e. not HTTP specific);
 * main functions are [[formatTimestamp]] to generate timestamps, [[getSigning]]
 * to derive the signing key, and [[signDigest]] or [[signChunk]] to sign a hash.
 */
/** */

import { createHmac } from 'crypto'

export interface SignOptions {
    /** Specify an alternate implementation of [[getSigningData]], i.e. a cached one */
    getSigningData?: GetSigningData
}

export interface SigningData {
    key: Buffer
    scope: string
}

export type GetSigningData = (dateStamp: string, secretKey: string,
    regionName: string, serviceName: string) => SigningData

export interface RelaxedCredentials {
    accessKey: string
    secretKey: string
    regionName?: string
    serviceName?: string
}

export interface Credentials extends RelaxedCredentials {
    regionName: string
    serviceName: string
}

/** Format the date stamp for [[getSigningData]] (low-level). */
export function formatDate(date?: Date) {
    const str = (date || new Date()).toISOString()
    if (str.length !== 24) {
        throw new Error('Unexpected ISO string when formatting date')
    }
    return str.substring(0, 10).replace(/-/g, '')
}

/**
 * Derive the signature key and credential scope (low-level)
 * 
 * `dateStamp` can be created with [[formatDate]]. Because it's cropped
 * to 8 characters, a full timestamp (see [[formatTimestamp]]) also works.
 * 
 * @returns Signing data (key and credentials scope)
 * @category Key derivation
 */
export function getSigningData(dateStamp: string, secretKey: string, regionName: string, serviceName: string): SigningData {
    dateStamp = dateStamp.substring(0, 8)
    const parts = [dateStamp, regionName, serviceName, 'aws4_request']
    let key = Buffer.from('AWS4' + secretKey)
    for (const part of parts) {
        key = createHmac('sha256', key).update(part).digest()
    }
    return { key, scope: parts.join('/') }
}

/** Make a simple reuse-previous-result cache for [[getSigningData]] */
getSigningData.makeSimpleCache = (): GetSigningData => {
    let key: string
    let value: SigningData
    return function _cached_getSigningData(a, b, c, d) {
        a = a.substring(0, 8)
        const nkey = [a,b,c,d].join('/')
        if (key !== nkey) {
            [ key, value ] = [ nkey, getSigningData(a,b,c,d) ]
        }
        return value
    }
}

/**
 * Convenience version of [[getSigningData]] that accepts a
 * `Credentials` object, and also returns a credential string.
 *
 * @param dateStamp The timestamp / date stamp
 * @param credentials Credentials to derive from
 * @returns Signing data and credential string
 * @category Key derivation
 */
export function getSigning(dateStamp: string, credentials: Credentials, options?: SignOptions) {
    const { accessKey, secretKey, regionName, serviceName } = credentials
    const derive = (options && options.getSigningData) || getSigningData
    const signing = derive(dateStamp, secretKey, regionName, serviceName)
    return { signing, credential: `${accessKey}/${signing.scope}` }
}

/** Format the timestamp for a request (low-level) */
export function formatTimestamp(date?: Date) {
    const str = (date || new Date()).toISOString()
    if (str.length !== 24) {
        throw new Error('Unexpected ISO string when formatting date')
    }
    return str.substring(0, 19).replace(/[:-]/g, '') + 'Z'
}

/**
 * Sign an arbitrary string using the derived key (low-level)
 * 
 * @param sts String to sign
 * @param key The signing key obtained from [[getSigningData]]
 * @returns The binary signature
 * @category Signing
 */
export const signString = (key: Buffer, sts: string | Buffer) =>
    createHmac('sha256', key).update(sts).digest()

/** Main algorithm ID, used by [[signDigest]] */
export const ALGORITHM = 'AWS4-HMAC-SHA256'

/**
 * Construct a standard payload digest string, and sign it with {{signString}}
 *
 * @param payloadDigest The payload digest (typically a hex-encoded SHA-256 hash)
 * @param timestamp Timestamp used in the request
 * @param signing The signing data obtained from [[getSigningData]] pr [[getSigning]] (its date should match `timestamp`)
 * @param algorithm Algorithm used for calculating `payloadDigest`, defaults to [[ALGORITHM]]
 * @returns The binary signature
 * @category Signing
 */
export const signDigest = (payloadDigest: string, timestamp: string,
        signing: SigningData, algorithm: string = ALGORITHM) =>
    signString(signing.key,
        [algorithm, timestamp, signing.scope, payloadDigest].join('\n'))

/** Chunk algorithm ID, used by [[signChunk]] */
export const ALGORITHM_CHUNK = 'AWS4-HMAC-SHA256-PAYLOAD'

/**
 * Variant of [[signDigest]] where the last signature and
 * an auxiliar digest is also included. Typically used to sign
 * the payload by chunks.
 *
 * @param lastSignature The last signature, hex-encoded. If this is the first
 *     chunk, pass the initial request signature (seed signature).
 * @param headersDigest The current headers digest (typically a hex-encoded SHA-256 hash)
 * @param payloadDigest The current payload digest (typically a hex-encoded SHA-256 hash)
 * @param timestamp Timestamp used in the request
 * @param signing The signing data obtained from [[getSigningData]] pr [[getSigning]] (its date should match `timestamp`)
 * @param algorithm Algorithm used for calculating `payloadDigest`, defaults to [[ALGORITHM_CHUNK]]
 * @returns The binary signature
 * @category Chunk signing
 */
export const signChunk = (lastSignature: string, headersDigest: string,
        payloadDigest: string, timestamp: string, signing: SigningData,
        algorithm: string = ALGORITHM_CHUNK) =>
    signDigest([lastSignature, headersDigest, payloadDigest].join('\n'),
        timestamp, signing, algorithm)
