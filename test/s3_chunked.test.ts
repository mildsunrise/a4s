import { promisify } from 'util'
import * as stream from 'stream'
import { getSigningData } from '../src/core'
import { SignedS3Request } from '../src/s3'
import { createS3PayloadSigner, signS3ChunkedRequest, CHUNK_MIN } from '../src/s3_chunked'
const finished = promisify(stream.finished)

const oDate = Date
const date = jest.spyOn(global, 'Date').mockImplementation(((s: any) => {
    return s ? new oDate(s) : new oDate(1567327663238)
}) as any)

describe('S3 Authorization-based Chunked Upload', () => {
    const credentials = {
        accessKey: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    }

    it('full test (includes incomplete chunk)', async () => {
        const payload1 = Buffer.alloc(25 * 1024, 'a')
        const payload2 = Buffer.alloc(40 * 1024, 'b')
        const chunkSize = 64 * 1024
        
        const request: SignedS3Request = {
            method: 'PUT',
            url: 'https://s3.amazonaws.com/examplebucket/chunkObject.txt',
            headers: {
                'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                'Content-Encoding': 'gzip',
            }
        }
        const { parameters, signer } = createS3PayloadSigner(
            credentials, request, payload1.length + payload2.length, chunkSize, { set: true })
        
        expect(parameters).toStrictEqual({
            'x-amz-date': '20190901T084743Z',
            'authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class, Signature=005ebbfad3a209227c1c8b72f89ab7658a27000ef7ce9a05f5ab02c2652c41e1',
            'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
            'Content-Encoding': 'aws-chunked,gzip',
            'x-amz-decoded-content-length': 66560,
            'content-length': 66824,
        })
        expect(request.headers).toStrictEqual({
            'x-amz-date': '20190901T084743Z',
            'x-amz-storage-class': 'REDUCED_REDUNDANCY',
            'authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class, Signature=005ebbfad3a209227c1c8b72f89ab7658a27000ef7ce9a05f5ab02c2652c41e1',
            'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
            'Content-Encoding': 'aws-chunked,gzip',
            'x-amz-decoded-content-length': 66560,
            'content-length': 66824,
        })
        
        const chunks: Buffer[] = []
        const done = finished(signer)
        signer.on('data', data => chunks.push(data))
        signer.write(payload1)
        signer.end(payload2)
        await done
        
        const expectedChunks = [
            Buffer.from('10000;chunk-signature=40dea6b4ea9bd6c8e4fd98005f81fdde029ec489f25b88494dcc673f2d642993\r\n'),
            Buffer.alloc(25 * 1024, 'a'),
            Buffer.alloc(39 * 1024, 'b'),
            Buffer.from('\r\n' + '400;chunk-signature=59b8ce104745550e9537da228264811f68e4fe1b693c6024ce18b100e83ae91e\r\n'),
            Buffer.alloc(1024, 'b'),
            Buffer.from('\r\n' + '0;chunk-signature=a2940d3b2c825f6b69ced9476eaf987b2998770501eceae97327d5b1c969c05e\r\n\r\n'),
        ]
        expect(chunks.map(x => x.toString()))
            .toStrictEqual(expectedChunks.map(x => x.toString()))
        expect(Buffer.concat(chunks).equals(Buffer.concat(expectedChunks)))
        expect(chunks[1]).toBe(payload1)

        expect(Buffer.concat(chunks).length)
            .toBe(request.headers!['content-length'])
    })

    it("doesn't touch content-encoding if already set correctly", () => {
        const request: SignedS3Request = {
            method: 'PUT',
            url: 'https://s3.amazonaws.com/examplebucket/chunkObject.txt',
            headers: {
                'x-amz-storage-class': 'REDUCED_REDUNDANCY',
                'Content-Encoding': '   aws-chunked ,gzip',
            }
        }
        const { parameters, signer } = createS3PayloadSigner(
            credentials, request, 65 * 1024, 64 * 1024, { set: true })
        
        expect(parameters).toStrictEqual({
            'x-amz-date': '20190901T084743Z',
            'authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class, Signature=857b1490b454d085e50983821e53811a488e8b5181608a3d870f0e13fc17edc0',
            'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
            'x-amz-decoded-content-length': 66560,
            'content-length': 66824,
        })
        expect(request.headers).toStrictEqual({
            'x-amz-date': '20190901T084743Z',
            'x-amz-storage-class': 'REDUCED_REDUNDANCY',
            'authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class, Signature=857b1490b454d085e50983821e53811a488e8b5181608a3d870f0e13fc17edc0',
            'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
            'Content-Encoding': '   aws-chunked ,gzip',
            'x-amz-decoded-content-length': 66560,
            'content-length': 66824,
        })
    })

    it("should throw when length doesn't match, and on extra calls", () => {
        const request: SignedS3Request = {
            method: 'PUT',
            url: 'https://s3.amazonaws.com/examplebucket/chunkObject.txt',
        }
        const { parameters, signer } = signS3ChunkedRequest(
            credentials, request, 65 * 1024, 64 * 1024, { set: true })
        expect(request.headers).toStrictEqual(parameters)
        expect(parameters).toStrictEqual({
            'x-amz-date': '20190901T084743Z',
            'authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length, Signature=89284808e144b475bc79365ea4646bb82af4186cc2c6f15bd094e06b8d27f71b',
            'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
            'content-encoding': 'aws-chunked',
            'x-amz-decoded-content-length': 66560,
            'content-length': 66824,
        })

        expect(() => signer()).toThrow()
        expect(() => signer(Buffer.alloc(0))).toThrow()
        expect(() => signer(Buffer.alloc(1024, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(64 * 1024 - 1, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(64 * 1024 + 1, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(64 * 1024, 'a'))).not.toThrow()

        expect(() => signer()).toThrow()
        expect(() => signer(Buffer.alloc(0))).toThrow()
        expect(() => signer(Buffer.alloc(64 * 1024, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(1024 - 1, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(1024 + 1, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(1024, 'a'))).not.toThrow()

        expect(() => signer(Buffer.alloc(1024, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(1024 + 1, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(64 * 1024, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(0, 'a'))).not.toThrow()

        expect(() => signer(Buffer.alloc(1024, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(1024 + 1, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(64 * 1024, 'a'))).toThrow()
        expect(() => signer(Buffer.alloc(0, 'a'))).toThrow()
        expect(() => signer()).toThrow()
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
        expect(() => createS3PayloadSigner(credentials,
            request, 0, CHUNK_MIN - 1)).toThrow()
        expect(request).toStrictEqual(request2)
        expect(() => createS3PayloadSigner(credentials,
            request, -1, CHUNK_MIN)).toThrow()
        expect(request).toStrictEqual(request2)
        expect(() => createS3PayloadSigner(credentials,
            request, 0, CHUNK_MIN + 0.1)).toThrow()
        expect(request).toStrictEqual(request2)
        expect(() => createS3PayloadSigner(credentials,
            request, 0.1, CHUNK_MIN)).toThrow()
        expect(request).toStrictEqual(request2)
        expect(() => createS3PayloadSigner(credentials,
            request, 0, CHUNK_MIN)).not.toThrow()
        expect(request).toStrictEqual(request2)
        
        async function test(payload: Buffer) {
            const { signer, parameters } = createS3PayloadSigner(credentials,
                request, payload.length, 8 * 1024)
            expect(request).toStrictEqual(request2)
            const chunks: Buffer[] = []
            const done = finished(signer)
            signer.on('data', data => chunks.push(data)).end(payload)
            await done
            expect(Buffer.concat(chunks).length).toBe(parameters['content-length'])
            return chunks
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
