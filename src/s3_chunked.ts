/**
 * This module implements S3 Chunked Upload signing, which is a
 * special form of the usual Authorization signing for S3 requests
 * which signs the payload progressively, without requiring you to
 * calculate its digest first. See {{autoSignRequestChunked}} and
 * {{createPayloadSigner}}.
 */

import { createHash } from 'crypto'
import { RequestOptions } from 'http'
import { Transform } from 'stream'

import { formatTimestamp, getSigningData, signDigest, RelaxedCredentials, SignOptions, SigningData } from './core'
import { SignHTTPOptions, CanonicalOptions, parseAuthorization } from './http'
import { autoSignRequestHeader } from './s3'
import { getHeader } from './util/headers'

/** Special value for payload digest, which indicates payload streaming encoding */
export const PAYLOAD_STREAMING = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'

/** Minimum length for chunks in payload streaming, 8KB */
export const CHUNK_MIN = 8 * 1024
/** Algorithm used for chunk signatures in payload streaming */
export const ALGORITHM_STREAMING = 'AWS4-HMAC-SHA256-PAYLOAD'

export interface ChunkDescription {
    hash: string
    length: number
}

export type ChunkSigner = (chunk?: Buffer | ChunkDescription) => string

// AWS docs don't mention it anywhere, but format needs to be exactly this:
// '[LENGTH];chunk-signature=[SIGNATURE]\r\n[BYTES]\r\n'
const CRLF = '\r\n'
const EMPTY_HASH = createHash('sha256').digest('hex')

function calculateChunks(bodyLength: number, chunkLength: number) {
    if (Math.floor(chunkLength) !== chunkLength || chunkLength < CHUNK_MIN) {
        throw new Error('Invalid chunk length')
    }
    if (Math.floor(bodyLength) !== bodyLength || bodyLength < 0) {
        throw new Error('Invalid body length')
    }
    const chunks = Math.floor(bodyLength / chunkLength)
    return { chunks, lastLength: bodyLength - chunks * chunkLength }
}

/**
 * Low-level function that calculates the signature for a chunk of
 * data. Most users should use {{createPayloadSigner}},
 * {{autoSignRequestChunked}}.
 * 
 * @param lastSignature Signature from previous chunk (or HTTP
 * request if this is the first chunk)
 * @param signing Signing data
 * @param timestamp Timestamp used for signing
 * @param chunk Chunk to calculate hash of (alternatively you may
 *              calculate it yourself and pass it as `{ hash: '<hex>' }`)
 * @returns Signature for the chunk
 */
export function signChunk(
    lastSignature: string,
    signing: SigningData,
    timestamp: string,
    chunk?: Buffer | { hash: string },
) {
    let hash = EMPTY_HASH
    if (chunk) {
        hash = Buffer.isBuffer(chunk) ?
            createHash('sha256').update(chunk).digest('hex') : chunk.hash
    }
    const digest = [lastSignature, EMPTY_HASH, hash].join('\n')
    return signDigest(ALGORITHM_STREAMING, digest, timestamp, signing).toString('hex')
}

/**
 * Special version of {{autoSignRequestHeader}} implementing 'payload
 * streaming', which allows you to send a signed payload in chunks,
 * without having to calculate its digest first.
 * 
 * Instead of returning the signed request, this function returns a
 * **chunk signer**. It's a function that should be called with each chunk
 * you want to send, and returns a header string that must be prepended
 * to it. When you have sent all the chunks, you should call it again
 * with no data to generate the trailing string.
 *
 * **Note:** All chunks must be of the passed `chunkLength`, except the
 * final one which can be smaller. An error will be thrown if you don't
 * adhere to this, or if the passed data doesn't match `bodyLength`. All
 * calls must pass data except for the final one.
 *
 * For a working example of use, see `demo_s3_upload`.
 * 
 * @param credentials Credentials to sign the request with
 * @param request Request to sign
 * @param bodyLength Length of the payload you want to send
 * @param chunkLength Length of each data chunk (must be at least CHUNK_MIN)
 * @param options Other options
 * @returns The chunk signing function
 */
export function autoSignRequestChunked(
    credentials: RelaxedCredentials,
    request: RequestOptions,
    bodyLength: number,
    chunkLength: number,
    options?: SignHTTPOptions & CanonicalOptions & SignOptions
): ChunkSigner {
    // Calculate total length (body + metadata)
    const { chunks, lastLength } = calculateChunks(bodyLength, chunkLength)
    const chunkHeader = `${chunkLength.toString(16)};chunk-signature=`
    const lastHeader = `${lastLength.toString(16)};chunk-signature=`
    const finalHeader = '0;chunk-signature='

    const totalLength = bodyLength + (chunkHeader.length + 64 + 4) * chunks
        + (lastLength ? lastHeader.length + 64 + 4 : 0) + finalHeader.length + 64 + 4

    // Prepare and sign the request
    const headers = request.headers = { ...request.headers! }
    let timestamp = (options || {}).timestamp || getHeader(headers, 'x-amz-date')[1]
    if (!timestamp) {
        timestamp = headers['x-amz-date'] = formatTimestamp()
    }
    const [ encodingName, encoding ] = getHeader(headers, 'content-encoding')
    if (!(encoding && /^aws-chunked($|,)/i.test(encoding))) {
        headers[encodingName] = 'aws-chunked' + (encoding ? `,${encoding}` : '')
    }
    headers['content-length'] = totalLength
    headers['x-amz-decoded-content-length'] = bodyLength
    autoSignRequestHeader(credentials, request, { hash: PAYLOAD_STREAMING }, options)

    // Derive key used by autoSignRequest
    const auth = parseAuthorization(request.headers!.authorization as string)
    const [ regionName, serviceName ] = auth.credential.split('/').slice(2, 4)
    const derive = (options && options.getSigningData) || getSigningData
    const signing = derive(timestamp, credentials.secretKey, regionName, serviceName)

    // Chunk signer implementation
    let dataCount = 0
    let signature = auth.signature.toString('hex')

    return function chunkSigner(chunk) {
        let length = 0, header = finalHeader
        if (chunk && chunk.length) {
            [ length, header ] = [ chunkLength, chunkHeader ]
            if (bodyLength - dataCount < chunkLength) {
                [ length, header ] = [ lastLength, lastHeader ]
            }
            if (chunk.length !== length) {
                throw new Error(`Unexpected chunk size (got ${chunk.length}, expected ${length})`)
            }
            dataCount += length
        } else if (dataCount !== bodyLength) {
            throw new Error('Empty chunks are not allowed, except for final one')
        }
        signature = signChunk(signature, signing, timestamp!, chunk)
        return (dataCount === length ? '' : CRLF) +
            header + signature + CRLF + (length ? '' : CRLF)
    }
}

/**
 * See {{autoSignRequestChunked}}. Instead of returning the chunk
 * signing function, this returns a `Transform` stream that does the
 * signing for you.
 *
 * Keep in mind an error will be thrown if the length of the
 * input data doesn't match the `bodyLength` you passed.
 *
 * @param credentials Credentials to sign the request with
 * @param request Request to sign
 * @param bodyLength Length of the payload you want to send
 * @param chunkLength Length of each data chunk (must be at least CHUNK_MIN)
 * @param options Other options
 * @returns The signing transform stream
 */
export function createPayloadSigner(
    credentials: RelaxedCredentials,
    request: RequestOptions,
    bodyLength: number,
    chunkLength: number,
    options?: SignHTTPOptions & CanonicalOptions & SignOptions
) {
    const signer = autoSignRequestChunked(credentials,
        request, bodyLength, chunkLength, options)

    let pending: Buffer[] = [], length = 0, hash = createHash('sha256')
    const pushData = (data: Buffer) => {
        pending.push(data)
        hash.update(data)
        length += data.length
    }
    const flushData = (stream: Transform) => {
        stream.push(signer({ hash: hash.digest('hex'), length }))
        pending.forEach(data => stream.push(data))
        pending = [], length = 0, hash = createHash('sha256')
    }

    return new Transform({
        transform(data: Buffer, _, callback) {
            if (length + data.length < chunkLength) {
                data.length && pushData(data)
                return callback()
            }
            pushData(data.slice(0, chunkLength - length))
            flushData(this)
            this._transform(data.slice(chunkLength - length), _, callback)
        },
        final(callback) {
            length && flushData(this)
            this.push(signer())
            callback()
        },
    })
}
