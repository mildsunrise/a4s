import { decodeEvent, decodeHeaders, encodeEvent, encodeEventHeaders, HeaderValue, HeaderArray, HeaderObject } from '../src/events'

describe('Event stream encoding', () => {
    it('decodes/encodes a simple event', () => {
        // AWS documentation is very incomplete and full of errors, and
        // these bytes are no exception... quick, everyone act surprised!
        const raw = Buffer.from(`
            AAAA0gAAAIKVoRFcDTpjb250ZW50LXR5cGUHABhhcHBsaWNhdGlvbi9vY3RldC1zdHJlYW0LOmV2ZW50LXR5
            cGUHAApBdWRpb0V2ZW50DTptZXNzYWdlLXR5cGUHAAVldmVudAxDb250ZW50LVR5cGUHABphcHBsaWNhdGlv
            bi94LWFtei1qc29uLTEuMVJJRkY88T0AV0FWRWZtdCAQAAAAAQABAIA+AAAAfQAAAgAQAGRhdGFU8D0AAAAA
            AAAAAAAAAAAA//8CAP3/BAC7QLFf
        `, 'base64')
        const data = Buffer.from(`
            UklGRjzxPQBXQVZFZm10IBAAAAABAAEAgD4AAAB9AAACABAAZGF0YVTwPQAAAAAAAAAAAAAAAAD//wIA/f8EAA==
        `, 'base64')
        const rawHeaders: HeaderArray = [
            [ ':content-type', { type: 'string', data: 'application/octet-stream' } ],
            [ ':event-type', { type: 'string', data: 'AudioEvent' } ],
            [ ':message-type', { type: 'string', data: 'event' } ],
            [ 'Content-Type', { type: 'string', data: 'application/x-amz-json-1.1' } ],
        ]
        const headers: HeaderObject = {
            ':content-type': { type: 'string', data: 'application/octet-stream' },
            ':event-type': { type: 'string', data: 'AudioEvent' },
            ':message-type': { type: 'string', data: 'event' },
            'Content-Type': { type: 'string', data: 'application/x-amz-json-1.1' },
        }
        const decoded = { rawHeaders, headers, data }

        expect(decodeEvent(raw)).toStrictEqual(decoded)
        expect(encodeEvent(decoded.rawHeaders, data)).toStrictEqual(raw)
        expect(encodeEventHeaders(decoded.rawHeaders, data.length))
            .toStrictEqual(raw.slice(0, raw.length - data.length - 4))
        
        expect(decodeEvent(encodeEvent(decoded.headers, data)).headers)
            .toStrictEqual(decoded.headers)
    })

    it('decodes/encodes an event with binary and uint64', () => {
        const raw = Buffer.from(`
            AAAAUwAAAEP1RHpYBTpkYXRlCAAAAWiXUkMLEDpjaHVuay1zaWduYXR1cmUGACCt6Zy+uymwEK2SrLp/zVBI
            5eGn83jdBwCaRUBJA+eaDafqjqI=
        `, 'base64')
        const data = Buffer.alloc(0)
        const rawHeaders: HeaderArray = [
            [ ':date', { type: 'uint64', data: BigInt(1548726977291) } ],
            [ ':chunk-signature', { type: 'buffer', data: Buffer.from('ade99cbebb29b010ad92acba7fcd5048e5e1a7f378dd07009a45404903e79a0d', 'hex') } ],
        ]
        const headers: HeaderObject = {
            ':date': { type: 'uint64', data: BigInt(1548726977291) },
            ':chunk-signature': { type: 'buffer', data: Buffer.from('ade99cbebb29b010ad92acba7fcd5048e5e1a7f378dd07009a45404903e79a0d', 'hex') },
        }
        const decoded = { rawHeaders, headers, data }

        expect(decodeEvent(raw)).toStrictEqual(decoded)
        expect(encodeEvent(decoded.rawHeaders, data)).toStrictEqual(raw)
        expect(encodeEventHeaders(decoded.rawHeaders, data.length))
            .toStrictEqual(raw.slice(0, raw.length - data.length - 4))

        expect(decodeEvent(encodeEvent(decoded.headers, data)).headers)
            .toStrictEqual(decoded.headers)
    })

    it('should throw on invalid event headers', () => {
        const build = (...chunks: any[]) => Buffer.concat(chunks.map(x => Buffer.from(x)))

        expect(decodeHeaders(build()))
            .toStrictEqual({ headers: {}, rawHeaders: [] })
        expect(decodeHeaders(build( [ 0, 7, 0, 0 ] ))).toStrictEqual({
            headers: { '': { type:'string', data: '' } },
            rawHeaders: [ [ '', { type:'string', data: '' } ] ] })
        expect(() => decodeHeaders(build( [ 8 ], 'toString', [ 7, 0, 0 ] )))
            .not.toThrow()
        
        // Ended unexpectedly
        expect(() => decodeHeaders(build( [ 0 ] ))).toThrow()
        expect(() => decodeHeaders(build( [ 4 ], 'hel' ))).toThrow()
        expect(() => decodeHeaders(build( [ 4 ], 'helo' ))).toThrow()
        expect(() => decodeHeaders(build( [ 4 ], 'helo', [ 8, 0, 0, 0, 0, 0, 0, 0 ] ))).toThrow()
        expect(() => decodeHeaders(build( [ 4 ], 'helo', [ 8, 0, 0, 0, 0, 0, 0, 0, 0 ] ))).not.toThrow()
        expect(() => decodeHeaders(build( [ 4 ], 'helo', [ 6, 0, 1 ] ))).toThrow()
        expect(() => decodeHeaders(build( [ 4 ], 'helo', [ 6, 0, 0 ] ))).not.toThrow()

        // Invalid type
        expect(() => decodeHeaders(build( [ 4 ], 'helo', [ 5, 0, 0 ] ))).toThrow()

        // Duplicate headers
        expect(() => decodeHeaders(build(
            [ 4 ], 'helo', [ 6, 0, 0 ], [ 4 ], 'helo', [ 6, 0, 0 ] ))).toThrow()
        expect(() => decodeHeaders(build(
            [ 4 ], 'helo', [ 6, 0, 0 ], [ 4 ], 'helo', [ 7, 0, 0 ] ))).toThrow()
        expect(() => decodeHeaders(build(
            [ 0 ], '', [ 6, 0, 0 ], [ 0 ], '', [ 7, 0, 0 ] ))).toThrow()
        expect(() => decodeHeaders(build(
            [ 4 ], 'helo', [ 6, 0, 0 ], [ 4 ], 'Helo', [ 7, 0, 0 ] ))).not.toThrow()
    })

    it('should throw on invalid event data', () => {
        const build = (...chunks: any[]) => Buffer.concat(chunks.map(x => Buffer.from(x)))

        // Too short
        expect(() => decodeEvent(build())).toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0 ] ))).toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0, 0 ] ))).toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0, 0, 0, 0, 0, 0 ] ))).toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0, 0, 0, 0, 0, 0, 0x65, 0x22, 0xdf ] ))).toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0, 16, 0, 0, 0, 0, 0x05, 0xc2, 0x48, 0xeb, 0x7d, 0x98, 0xc8 ] ))).toThrow()

        // Invalid lengths
        expect(() => decodeEvent(build( [ 0, 0, 0, 0, 0, 0, 0, 0, 0x65, 0x22, 0xdf, 0x69, 0x7e, 0x2a, 0x53, 0xfc ] ))).toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0, 16, 0, 0, 0, 0, 0x05, 0xc2, 0x48, 0xeb, 0x7d, 0x98, 0xc8, 0xff ] ))).not.toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0, 16, 0, 0, 0, 1, 0x72, 0xc5, 0x78, 0x7d, 0x75, 0x75, 0x6f, 0x6d ] ))).toThrow()

        // Wrong CRC
        expect(() => decodeEvent(build( [ 0, 0, 0, 16, 0, 0, 0, 0, 0x05, 0xc2, 0x48, 0xeb, 0x7d, 0x98, 0xc8, 0xfe ] ))).toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0, 16, 0, 0, 0, 0, 0x05, 0xc2, 0x48, 0xec, 0x7d, 0x98, 0xc8, 0xff ] ))).toThrow()
        expect(() => decodeEvent(build( [ 0, 0, 0, 16, 0, 0, 0, 0, 0x05, 0xc2, 0x48, 0xec, 0xe3, 0xfc, 0x5d, 0x5c ] ))).toThrow()
    })

    it('should throw when encoding invalid headers', () => {
        // Invalid type
        expect(() => encodeEventHeaders([[ 'test', { type: 'foo' as 'string', data: '' } ]], 0)).toThrow()

        // Header value too long
        expect(() => encodeEventHeaders([[ 'test', { type: 'string', data: 'a'.repeat(0xFFFF) } ]], 0)).not.toThrow()
        expect(() => encodeEventHeaders([[ 'test', { type: 'string', data: 'a'.repeat(0xFFFF + 1) } ]], 0)).toThrow()

        // Header name too long
        expect(() => encodeEventHeaders([[ 'a'.repeat(0xFF), { type: 'string', data: 'test' } ]], 0)).not.toThrow()
        expect(() => encodeEventHeaders([[ 'a'.repeat(0xFF + 1), { type: 'string', data: 'test' } ]], 0)).toThrow()
    })
})
