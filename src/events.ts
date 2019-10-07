/**
 * This module implements *event stream encoding* used for the
 * AWS Transcribe streaming API (see {{encodeEvent}}, {{decodeEvent}}).
 * It doesn't implement any signing logic, just the binary format.
 */
/** */

import crc32 from './util/crc32'

/** MIME type string for an event stream */
export const MIME_TYPE = 'application/vnd.amazon.eventstream'

/**
 * Represents the value of a header. `type` specifies the
 * kind of value, and `data` contains the value itself. Currently,
 * there are 3 types: `string` (variable length string), `buffer`
 * (variable length binary content), and `uint64` (encodes a 64-bit
 * integer).
 */
export type HeaderValue = {
    type: 'string'
    data: string
} | {
    type: 'buffer' | 'uuid'
    data: Buffer
} | {
    type: 's64'
    data: bigint
} | {
    type: 's32' | 's16' | 's8'
    data: number
} | {
    type: 'boolean'
    data: boolean
} | {
    type: 'timestamp'
    data: Date
}

export type HeaderObject = { [name: string]: HeaderValue }
export type HeaderArray = [ string, HeaderValue ][]

const TYPE_TRUE = 0
const TYPE_FALSE = 1
const TYPE_S8 = 2
const TYPE_S16 = 3
const TYPE_S32 = 4
const TYPE_S64 = 5
const TYPE_BINARY = 6
const TYPE_STRING = 7
const TYPE_TIMESTAMP = 8
const TYPE_UUID = 9

/// PARSING ///

/**
 * Decode headers.
 *
 * @param data Event header data
 * @throws If there is extra / missing data, if header name is not UTF-8,
 *     if header type is unknown, if header value is invalid, or if there
 *     are duplicate headers
 * @returns Object with: `rawHeaders`, array of header pairs (`[name, value]`);
 *     and `headers`, an object with the names as its keys.
 */
export function decodeHeaders(data: Buffer) {
    const result: HeaderArray = []
    let i = 0
    function consume(n: number) {
        let t = i
        if ((i += n) > data.length) {
            throw new Error('Headers ended unexpectedly')
        }
        return t
    }
    while (i < data.length) {
        const nameLength = data[consume(1)]
        // FIXME: throw if not valid UTF-8
        const name = data.slice(consume(nameLength), i).toString()
        const type = data[consume(1)]
        if (type === TYPE_TRUE || type === TYPE_FALSE) {
            result.push([ name, { type: 'boolean', data: type === TYPE_TRUE } ])
        } else if (type === TYPE_BINARY || type === TYPE_STRING) {
            const valueLength = data.readUInt16BE(consume(2))
            const x = data.slice(consume(valueLength), i)
            // FIXME: throw if not valid UTF-8
            result.push([ name, type === TYPE_STRING ?
                { type: 'string', data: x.toString() } :
                { type: 'buffer', data: x } ])
        } else if (type === TYPE_S8) {
            result.push([ name, { type: 's8', data: data.readInt8(consume(1)) } ])
        } else if (type === TYPE_S16) {
            result.push([ name, { type: 's16', data: data.readInt16BE(consume(2)) } ])
        } else if (type === TYPE_S32) {
            result.push([ name, { type: 's32', data: data.readInt32BE(consume(4)) } ])
        } else if (type === TYPE_S64) {
            result.push([ name, { type: 's64', data: data.readBigInt64BE(consume(8)) } ])
        } else if (type === TYPE_TIMESTAMP) {
            const x = Number(data.readBigInt64BE(consume(8)))
            result.push([ name, { type: 'timestamp', data: new Date(x) } ])
        } else if (type === TYPE_UUID) {
            result.push([ name, { type: 'uuid', data: data.slice(consume(16), i) } ])
        } else {
            throw new Error(`Unknown header type ${type}`)
        }
    }

    const headers: HeaderObject = {}
    result.forEach(([ name, value ]) => {
        if ({}.hasOwnProperty.call(headers, name)) {
            throw new Error(`Duplicate header ${name} found`)
        }
        headers[name] = value
    })
    return { rawHeaders: result, headers }
}

function checkCRC(name: string, actual: number, expected: number) {
    if (actual !== expected) {
        throw new Error(`${name} CRC doesn't match (got ${actual}, calculated ${expected})`)
    }
}

/**
 * Decode a buffer, which is expected to contain exactly *one* event,
 * into the headers and data.
 * 
 * @param event The binary event data
 * @throws If header length is invalid, CRCs don't match, data ends
 *     unexpectedly, headers end unexpectedly, or headers are invalid/duplicate
 * @return Object with `data` (Buffer),
 *     `headers` and `rawHeaders` (see [[decodeHeaders]])
 */
export function decodeEvent(event: Buffer) {
    if (event.length < 12) {
        throw new Error('Event data ended unexpectedly')
    }
    if (event.readUInt32BE(0) !== event.length) {
        throw new Error("Total length doesn't match")
    }
    const headersLength = event.readUInt32BE(4)
    checkCRC('prelude', event.readInt32BE(8), crc32(event.slice(0, 8)))

    const dataStart = 12 + headersLength, dataEnd = event.length - 4
    if (dataStart > dataEnd) {
        throw new Error('Invalid header length')
    }
    const headers = event.slice(12, dataStart)
    const data = event.slice(dataStart, dataEnd)
    checkCRC('message', event.readInt32BE(dataEnd), crc32(event.slice(0, dataEnd)))

    return { ...decodeHeaders(headers), data }
}

/// ENCODING ///

function encodeHeaderValue(value: HeaderValue): [ number, Buffer ] {
    const bp = Buffer.prototype
    const simpleNumber = <T> (value: { data: T }, type: number, n: number,
        method: (x: T, o: number) => any): [ number, Buffer ] => {
        const b = Buffer.allocUnsafe(n)
        method.call(b, value.data, 0)
        return [ type, b ]
    }

    if (value.type === 'string' || value.type === 'buffer') {
        const data = value.type === 'string' ?
            Buffer.from(value.data) : value.data
        const type = value.type === 'string' ? TYPE_STRING : TYPE_BINARY
        if (data.length > 0xFFFF) {
            throw new Error('Header value is too big')
        }
        const result = Buffer.allocUnsafe(2 + data.length)
        result.writeUInt16BE(data.length, 0)
        data.copy(result, 2)
        return [ type, result ]
    } else if (value.type === 'boolean') {
        return [ value.data ? TYPE_TRUE : TYPE_FALSE, Buffer.alloc(0) ]
    } else if (value.type === 's8') {
        return simpleNumber(value, TYPE_S8, 1, bp.writeInt8)
    } else if (value.type === 's16') {
        return simpleNumber(value, TYPE_S16, 2, bp.writeInt16BE)
    } else if (value.type === 's32') {
        return simpleNumber(value, TYPE_S32, 4, bp.writeInt32BE)
    } else if (value.type === 's64') {
        return simpleNumber(value, TYPE_S64, 8, bp.writeBigInt64BE)
    } else if (value.type === 'timestamp') {
        const data = BigInt(value.data.getTime())
        return simpleNumber({ data }, TYPE_TIMESTAMP, 8, bp.writeBigInt64BE)
    } else if (value.type === 'uuid') {
        if (value.data.length !== 16) {
            throw new TypeError(`UUID data has invalid length ${value.data.length}`)
        }
        return [ TYPE_UUID, value.data ]
    }
    throw new Error('Illegal header type specified')
}

/**
 * Encode event headers
 * 
 * @param headers Event headers
 * @throws If header name / value is too big
 * @returns Encoded headers
 */
export function encodeHeaders(headers: HeaderArray | HeaderObject) {
    const headerArray: HeaderArray = Array.isArray(headers) ? headers :
        Object.keys(headers).map(k => [ k, headers[k] ])
    return Buffer.concat(headerArray.map(([ nameStr, valueObj ]) => {
        const name = Buffer.from(nameStr)
        if (name.length > 0xFF) {
            throw new Error('Header name is too big')
        }
        const [ type, value ] = encodeHeaderValue(valueObj)
        const header = Buffer.allocUnsafe(1 + name.length + 1 + value.length)
        header[0] = name.length
        name.copy(header, 1)
        header[1 + name.length] = type
        value.copy(header, 1 + name.length + 1)
        return header
    }))
}

/**
 * Generates a header for an event, which should be prepended to
 * the payload. Use this instead of [[encodeEvent]] if you have a
 * huge payload and want to avoid copying.
 * 
 * **Note**: After the payload, you should also send a big-endian
 * CRC32 of the headers + payload.
 * 
 * @param headers Event headers
 * @param dataLength Event payload length (in bytes)
 * @throws If header name / value is too big, or dataLength is invalid
 * @returns Header bytes
 */
export function encodeEventHeaders(headers: HeaderArray | HeaderObject, dataLength: number) {
    const headersData = encodeHeaders(headers)
    const event = Buffer.alloc(12 + headersData.length)
    event.writeUInt32BE(event.length + dataLength + 4, 0)
    event.writeUInt32BE(headersData.length, 4)
    event.writeInt32BE(crc32(event.slice(0, 8)), 8)
    headersData.copy(event, 12)
    return event
}

/**
 * Given headers and payload, encode an event into a single buffer.
 * 
 * @param headers Event headers
 * @param data Event payload
 * @throws If header name / value is too big
 * @returns Event data
 */
export function encodeEvent(headers: HeaderArray | HeaderObject, data: Buffer) {
    const eventHeaders = encodeEventHeaders(headers, data.length)
    const event = Buffer.alloc(eventHeaders.length + data.length + 4)
    eventHeaders.copy(event, 0)
    data.copy(event, eventHeaders.length)
    event.writeInt32BE(crc32(event.slice(0, event.length - 4)), event.length - 4)
    return event
}
