import { HeaderObject } from '../src/events'
import { signEvent } from '../src/events_sign'

describe('Event signing', () => {
    it('Basic test', () => {
        const headers: HeaderObject = {
            ':date': { type: 'timestamp', data: new Date(1570448107486) },
        }
        const result = signEvent('last', {
            secretKey: 'testKey', accessKey: 'testID',
            serviceName: 'kinesis', regionName: 'us-west-1',
        }, headers, Buffer.alloc(7, 'a'), { set: true })
        expect(result).toStrictEqual({
            params: {
                ':chunk-signature': { type: 'buffer', data: Buffer.from('e57109fb79b79cec1971740147778349d45e7f7b6ebcff6165171c37075ec939', 'hex') },
            },
            signature: Buffer.from('e57109fb79b79cec1971740147778349d45e7f7b6ebcff6165171c37075ec939', 'hex'),
            signing: {
                key: Buffer.from('f2eb1e265149130d538bcaac92ea5156e0467db76ce39b7c52ca0858ac4d31b1', 'hex'),
                scope: '20191007/us-west-1/kinesis/aws4_request',
            },
            timestamp: '20191007T113507Z',
        })
        expect(headers).toStrictEqual({
            ':date': { type: 'timestamp', data: new Date(1570448107486) },
            ':chunk-signature': { type: 'buffer', data: Buffer.from('e57109fb79b79cec1971740147778349d45e7f7b6ebcff6165171c37075ec939', 'hex') },
        })
    })

    // FIXME: does case matter? is uppercase allowed? how is sorting done?
})
