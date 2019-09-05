/**
 * Code for signing generic messages using AWS Signature version 4.
 * 
 * This module contains only common signing logic (i.e. not HTTP specific).
 */

import { createHmac } from 'crypto'

export interface SignOptions {
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

/** Format the date stamp for getSigningData (low-level). */
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
 * `dateStamp` can be created with {{formatDate}}. Because it's cropped
 * to 8 characters, a full timestamp (see {{formatTimestamp}}) also works.
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

/** Make a simple reuse-previous-result cache for getSigningData */
getSigningData.makeSimpleCache = (): GetSigningData => {
    let key: string
    let value: SigningData
    return function _cached_getSigningData(a, b, c, d) {
        const nkey = [a,b,c,d].join('/')
        if (key !== nkey) {
            [ key, value ] = [ nkey, getSigningData(a,b,c,d) ]
        }
        return value
    }
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
 * @param key The signing key obtained from {{getSigningData}}
 * @returns The binary signature
 */
export const signString = (key: Buffer, sts: string | Buffer) =>
    createHmac('sha256', key).update(sts).digest()

/** Main algorithm ID */
export const MAIN_ALGORITHM = 'AWS4-HMAC-SHA256'

/**
 * Construct and sign a standard payload digest string (low-level)
 *
 * @param algorithm Algorithm used for calculating `payloadDigest`, i.e. `AWS4-HMAC-SHA256`
 * @param payloadDigest The payload digest (typically hex-encoded)
 * @param timestamp Timestamp used in the request
 * @param signing The signing data obtained from {{getSigningData}} (its date should match `timestamp`)
 * @returns The binary signature
 */
export const signDigest = (algorithm: string, payloadDigest: string,
                           timestamp: string, signing: SigningData) =>
    signString(signing.key,
        [algorithm, timestamp, signing.scope, payloadDigest].join('\n'))

/**
 * High-level function that uses {{getSigningData}} to derive
 * signing key / scope, and then {{signDigest}} to calculate
 * the signature.
 *
 * @param credentials Info to derive key and credentials scope
 * @param algorithm Algorithm used for calculating `payloadDigest`, i.e. `AWS4-HMAC-SHA256`
 * @param payloadDigest The payload digest
 * @param timestamp Timestamp used in the request
 * @returns The signature and credential string
 */
export function sign(credentials: Credentials, algorithm: string, payloadDigest: string, timestamp: string, options?: SignOptions) {
    const { accessKey, secretKey, regionName, serviceName } = credentials
    const derive = (options && options.getSigningData) || getSigningData
    const signing = derive(timestamp, secretKey, regionName, serviceName)
    const signature = signDigest(algorithm, payloadDigest, timestamp, signing)
    return { signature, credential: `${accessKey}/${signing.scope}` }
}
