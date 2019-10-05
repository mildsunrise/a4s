/**
 * This module implements *event stream encoding* used for the
 * AWS Transcribe streaming API (see {{encodeEvent}}, {{decodeEvent}}).
 * It doesn't implement any signing logic, just the binary format.
 */
/** */

import crc32 from './util/crc32'

export type HeaderValue = {
    type: 'string'
    data: string
} | {
    type: 'uint64'
    data: bigint
} | {
    type: 'buffer'
    data: Buffer
}

export type HeaderObject = { [name: string]: HeaderValue }
export type HeaderArray = [ string, HeaderValue ][]

const HEADER_TYPE_BINARY = 6
const HEADER_TYPE_STRING = 7
const HEADER_TYPE_UINT64 = 8

/// PARSING ///

/**
 * Decode header data from an event, into an array of `RawHeader`.
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
        if (type === HEADER_TYPE_BINARY || type === HEADER_TYPE_STRING) {
            const valueLength = data.readUInt16BE(consume(2))
            const cdata = data.slice(consume(valueLength), i)
            // FIXME: throw if not valid UTF-8
            result.push([ name, type === HEADER_TYPE_BINARY ?
                { type: 'buffer', data: cdata } :
                { type: 'string', data: cdata.toString() } ])
        } else if (type === HEADER_TYPE_UINT64) {
            const cdata = data.slice(consume(8), i).readBigUInt64BE()
            result.push([ name, { type: 'uint64', data: cdata } ])
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
    if (value.type === 'string' || value.type === 'buffer') {
        const data = value.type === 'string' ?
            Buffer.from(value.data) : value.data
        const type = value.type === 'string' ?
            HEADER_TYPE_STRING : HEADER_TYPE_BINARY
        if (data.length > 0xFFFF) {
            throw new Error('Header value is too big')
        }
        const result = Buffer.allocUnsafe(2 + data.length)
        result.writeUInt16BE(data.length, 0)
        data.copy(result, 2)
        return [ type, result ]
    } else if (value.type === 'uint64') {
        const result = Buffer.allocUnsafe(8)
        result.writeBigUInt64BE(value.data)
        return [ HEADER_TYPE_UINT64, result ]
    }
    throw new Error('Illegal header type specified')
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
 * @throws If header name / value is too big
 * @returns Header bytes
 */
export function encodeEventHeaders(headers: HeaderArray | HeaderObject, dataLength: number) {
    const headerArray: HeaderArray = Array.isArray(headers) ? headers :
        Object.keys(headers).map(k => [ k, headers[k] ])
    const headersData = Buffer.concat(headerArray.map(([ nameStr, valueObj ]) => {
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
