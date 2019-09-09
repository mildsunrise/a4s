import { promisify } from 'util'
import * as stream from 'stream'
import { getSigningData } from '../src/core'
import { signS3Policy, SignedS3Request, signS3Request } from '../src/s3'
import { createPayloadSigner, signS3Chunk, CHUNK_MIN } from '../src/s3_chunked'
const finished = promisify(stream.finished)

const oDate = Date
const date = jest.spyOn(global, 'Date').mockImplementation(((s: any) => {
    return s ? new oDate(s) : new oDate(1567327663238)
}) as any)

describe('S3 signing', () => {
    const credentials = {
        accessKey: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    }

    describe('Authorization-based', () => {
        it('basic test', () => {
            const request = {
                url: 'https://examplebucket.s3.amazonaws.com/root//folder A?list-type=2',
            }
            const request2 = { ...request }
            const headers1 = signS3Request(credentials, request2)
            expect(request2).toStrictEqual(request)
            expect(headers1).toStrictEqual({
                'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'x-amz-date': '20190901T084743Z',
                authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=26e0ce918d316644d24ede2e351ed6b727ce2740527721c5631a494629f54bfb'
            })

            const headers2 = signS3Request(credentials, request2, { set: true })
            expect(headers1).toStrictEqual(headers2)
            expect(request2).toStrictEqual({
                url: 'https://examplebucket.s3.amazonaws.com/root//folder A?list-type=2',
                headers: {
                    'x-amz-content-sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                    'x-amz-date': '20190901T084743Z',
                    authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=26e0ce918d316644d24ede2e351ed6b727ce2740527721c5631a494629f54bfb'
                }
            })
        })
    })

    describe('query based', () => {
        it('basic test', () => {
            const request = {
                url: 'https://examplebucket.s3.amazonaws.com/root//folder A?list-type=2',
            }
            const request2 = { ...request }
            const query1 = signS3Request(credentials, request2, { query: true })
            expect(request2).toStrictEqual(request)
            expect(query1).toStrictEqual({
                'X-Amz-Expires': '604800',
                'X-Amz-Date': '20190901T084743Z',
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': 'AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request',
                'X-Amz-SignedHeaders': 'host',
                'X-Amz-Signature': '2a90f4809bc072d7e58b670b7888dbb932f405f355169ebb9fba2dd27f939153'
            })

            const query2 = signS3Request(credentials, request2, { query: true, set: true })
            expect(query1).toStrictEqual(query2)
            expect(request2).toStrictEqual({
                url: 'https://examplebucket.s3.amazonaws.com/root//folder%20A?list-type=2&X-Amz-Expires=604800&X-Amz-Date=20190901T084743Z&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20190901%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=2a90f4809bc072d7e58b670b7888dbb932f405f355169ebb9fba2dd27f939153'
            })
        })
    })

    describe('Authorization-based Chunked Upload', () => {
        
        it('signChunk() test', () => {
            const timestamp = '20130524T000000Z'
            const signing = getSigningData(timestamp, credentials.secretKey, 'us-east-1', 's3')
            const lastSignature = '4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9'
            const hash = 'bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a'
            expect(signS3Chunk(lastSignature, signing, timestamp, { hash }))
                .toBe('ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648')
        })

        it('full test (includes incomplete chunk)', async () => {
            const payload = Buffer.alloc(65 * 1024, 'a')
            const chunkSize = 64 * 1024
            
            const request: SignedS3Request = {
                method: 'PUT',
                url: 'https://s3.amazonaws.com/examplebucket/chunkObject.txt',
                headers: {
                    'x-amz-date': '20130524T000000Z',
                    'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                }
            }
            const { signer } = createPayloadSigner(
                credentials, request, payload.length, chunkSize, { set: true })
            
            expect(request.headers).toStrictEqual({
                'x-amz-date': '20130524T000000Z',
                'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                'authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class, Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9',
                'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
                'content-encoding': 'aws-chunked',
                'x-amz-decoded-content-length': 66560,
                'content-length': 66824,
            })
            
            const chunks: Buffer[] = []
            const done = finished(signer)
            signer.on('data', data => chunks.push(data)).end(payload)
            await done
            
            const expectedChunks = [
                Buffer.from('10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\r\n'),
                Buffer.alloc(64 * 1024, 'a'),
                Buffer.from('\r\n' + '400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\r\n'),
                Buffer.alloc(1024, 'a'),
                Buffer.from('\r\n' + '0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9\r\n\r\n'),
            ]
            expect(chunks.map(x => x.toString()))
                .toStrictEqual(expectedChunks.map(x => x.toString()))
            expect(Buffer.concat(chunks).equals(Buffer.concat(expectedChunks)))
            
            expect(Buffer.concat(chunks).length)
                .toBe(request.headers!['content-length'])
        })
        
        it('edge cases', async () => {
            const requestbuilder = (): SignedS3Request => ({
                method: 'PUT',
                url: 'https://s3.amazonaws.com/examplebucket/chunkObject.txt',
                headers: {
                    'x-amz-date': '20130524T000000Z',
                    'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                }
            })
            const request = requestbuilder(), request2 = requestbuilder()
            expect(() => createPayloadSigner(credentials,
                request, 0, CHUNK_MIN - 1)).toThrow()
            expect(request).toStrictEqual(request2)
            expect(() => createPayloadSigner(credentials,
                request, -1, CHUNK_MIN)).toThrow()
            expect(request).toStrictEqual(request2)
            expect(() => createPayloadSigner(credentials,
                request, 0, CHUNK_MIN + 0.1)).toThrow()
            expect(request).toStrictEqual(request2)
            expect(() => createPayloadSigner(credentials,
                request, 0.1, CHUNK_MIN)).toThrow()
            expect(request).toStrictEqual(request2)
            expect(() => createPayloadSigner(credentials,
                request, 0, CHUNK_MIN)).not.toThrow()
            expect(request).toStrictEqual(request2)
            
            function test(payload: Buffer) {
                const { signer } = createPayloadSigner(credentials,
                    request, payload.length, 8 * 1024)
                expect(request).toStrictEqual(request2)
                const chunks: Buffer[] = []
                const done = finished(signer)
                signer.on('data', data => chunks.push(data)).end(payload)
                return done.then(() => chunks)
            }
            expect(await test(Buffer.alloc(0 * 1024, 'a'))).toStrictEqual([
                Buffer.from('0;chunk-signature=4971b6d742bda0ea643093cbcd6299f5f4e75296bfacdcd30a1f96d304194ddc\r\n\r\n'),
            ])
            expect(await test(Buffer.alloc(1 * 1024, 'a'))).toStrictEqual([
                Buffer.from('400;chunk-signature=d445d8121f9806753d2eee4ae2ef32b0db807f7936004801844cf310e65aedab\r\n'),
                Buffer.alloc(1 * 1024, 'a'),
                Buffer.from('\r\n' + '0;chunk-signature=c4da9a2b9d795acf15afa6acfbc56378a4962bbe493c76576d2f83b0b364f5eb\r\n' + '\r\n'),
            ])
            expect(await test(Buffer.alloc(8 * 1024, 'a'))).toStrictEqual([
                Buffer.from('2000;chunk-signature=da06b60b0db5eba4e3ea816508b742c0a6bdd28b63cebf62d2bc15cde1a92dcc\r\n'),
                Buffer.alloc(8 * 1024, 'a'),
                Buffer.from('\r\n' + '0;chunk-signature=eba969055bc72bb601a692fb47b5b9753b121f114a892fec8e410e16f5caf373\r\n' + '\r\n'),
            ])
            expect(await test(Buffer.alloc(24 * 1024, 'a'))).toStrictEqual([
                Buffer.from('2000;chunk-signature=9c1c1a3a438118950e29a2112c35c1790f1bb1bde4e465799e4665cbb4c90b69\r\n'),
                Buffer.alloc(8 * 1024, 'a'),
                Buffer.from('\r\n' + '2000;chunk-signature=a35ecc42af91e72ad54063484d73aa6ae0ff8966b95fb41346828997bcd38936\r\n'),
                Buffer.alloc(8 * 1024, 'a'),
                Buffer.from('\r\n' + '2000;chunk-signature=deb564f6a467d04910531823f6091855129550e53e437b6f9f594ac7d01a3dc0\r\n'),
                Buffer.alloc(8 * 1024, 'a'),
                Buffer.from('\r\n' + '0;chunk-signature=f5c958803bef486ebd0688607f1234eddc642aab99d596fdb075a02808af6a6b\r\n' + '\r\n'),
            ])
        })

    })

    describe('POST form based', () => {
        it('should sign a policy correctly', () => {
            const srcPolicy = {
                expires: new Date(1567327687881).toISOString(),
            }
            date.mockClear()
            const params = signS3Policy(
                { ...credentials, regionName: 'eu-west-2' },
                srcPolicy,
            )
            expect(date).toHaveBeenCalledTimes(1)
            const policy = JSON.parse(Buffer.from(params.policy!, 'base64').toString())
            expect(policy).toStrictEqual({
                expires: '2019-09-01T08:48:07.881Z',
                conditions: [
                    { 'x-amz-date': '20190901T084743Z' },
                    { 'x-amz-algorithm': 'AWS4-HMAC-SHA256' },
                    { 'x-amz-credential': 'AKIAIOSFODNN7EXAMPLE/20190901/eu-west-2/s3/aws4_request' },
                ]
            })
            expect(params).toStrictEqual({
                policy: 'eyJleHBpcmVzIjoiMjAxOS0wOS0wMVQwODo0ODowNy44ODFaIiwiY29uZGl0aW9ucyI6W3sieC1hbXotZGF0ZSI6IjIwMTkwOTAxVDA4NDc0M1oifSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lBSU9TRk9ETk43RVhBTVBMRS8yMDE5MDkwMS9ldS13ZXN0LTIvczMvYXdzNF9yZXF1ZXN0In1dfQ==',
                'x-amz-date': '20190901T084743Z',
                'x-amz-algorithm': 'AWS4-HMAC-SHA256',
                'x-amz-credential': 'AKIAIOSFODNN7EXAMPLE/20190901/eu-west-2/s3/aws4_request',
                'x-amz-signature': 'c3ce6aeeaa95c11abccd1689a83bba274e28c83b4be080978e7863108bd6edf0',
            })
        })

        it('should obey if we force service / region', () => {
            const params = signS3Policy(
                { ...credentials, serviceName: 'test', regionName: 'reg' },
                {
                    expires: new Date(1567327687881).toISOString(),
                    conditions: [
                        { param: 'value' },
                    ],
                },
                { timestamp: '20190901T084743Z' }
            )
            const policy = JSON.parse(Buffer.from(params.policy!, 'base64').toString())
            expect(policy).toStrictEqual({
                expires: '2019-09-01T08:48:07.881Z',
                conditions: [
                    { param: 'value' },
                    { 'x-amz-date': '20190901T084743Z' },
                    { 'x-amz-algorithm': 'AWS4-HMAC-SHA256' },
                    { 'x-amz-credential': 'AKIAIOSFODNN7EXAMPLE/20190901/reg/test/aws4_request' },
                ]
            })
            expect(params).toStrictEqual({
                policy: 'eyJleHBpcmVzIjoiMjAxOS0wOS0wMVQwODo0ODowNy44ODFaIiwiY29uZGl0aW9ucyI6W3sicGFyYW0iOiJ2YWx1ZSJ9LHsieC1hbXotZGF0ZSI6IjIwMTkwOTAxVDA4NDc0M1oifSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lBSU9TRk9ETk43RVhBTVBMRS8yMDE5MDkwMS9yZWcvdGVzdC9hd3M0X3JlcXVlc3QifV19',
                'x-amz-date': '20190901T084743Z',
                'x-amz-algorithm': 'AWS4-HMAC-SHA256',
                'x-amz-credential': 'AKIAIOSFODNN7EXAMPLE/20190901/reg/test/aws4_request',
                'x-amz-signature': 'bf8556b10d72a9730810f3ba8f75c1fe35700ad2e152bd35cb1a0fd87a0f0477',
            })
        })
    })

})    
