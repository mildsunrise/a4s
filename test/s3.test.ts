import { URLSearchParams } from 'url'
import { signS3Policy, signS3Request, SignedS3Request } from '../src/s3'

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
            const request2: SignedS3Request = { ...request }
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

            // signing request again should produce same result
            const request3 = { url: request2.url, headers: { ...request2.headers } }
            const headers3 = signS3Request(credentials, request3)
            expect(request3).toStrictEqual(request2)
            expect({ ...headers2, ...headers3 }).toStrictEqual(headers2) // headers3 must be subset of headers2
            const headers4 = signS3Request(credentials, request3, { set: true })
            expect(request3).toStrictEqual(request2)
            expect(headers4).toStrictEqual(headers3)
        })

        it('pre-existing headers', () => {
            const requestbuilder = () => ({
                url: {
                    pathname: '/folder A',
                },
                headers: {
                    'x-aMz-content-sha256': 'overriden',
                    'foo': 'bar',
                }
            })
            const request = requestbuilder(), request2 = requestbuilder()
            const headers1 = signS3Request(credentials, request2)
            expect((request2.url as any).host).toBe('s3.amazonaws.com')
            delete (request2.url as any).host
            expect(request2).toStrictEqual(request)
            expect(headers1).toStrictEqual({
                'x-amz-date': '20190901T084743Z',
                authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=foo;host;x-amz-content-sha256;x-amz-date, Signature=7f7e4fb707ee43d80f2bc8f69e41a6ac4105991a7f1f665dc70d3828612e0391'
            })

            const headers2 = signS3Request(credentials, request2, { set: true })
            expect(headers1).toStrictEqual(headers2)
            expect(request2).toStrictEqual({
                url: {
                    host: 's3.amazonaws.com',
                    pathname: '/folder A',
                },
                headers: {
                    'x-aMz-content-sha256': 'overriden',
                    'foo': 'bar',
                    'x-amz-date': '20190901T084743Z',
                    authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=foo;host;x-amz-content-sha256;x-amz-date, Signature=7f7e4fb707ee43d80f2bc8f69e41a6ac4105991a7f1f665dc70d3828612e0391'
                }
            })
        })

        it('unsigned payload', () => {
            const requestbuilder = () => ({
                url: {
                    host: 'example.s3.us-east-1.amazonaws.com:80',
                    pathname: '/folder A',
                    searchParams: new URLSearchParams({ 'list-type': '2' })
                },
                headers: {
                    'foo': 'bar',
                },
                body: 'should be ignored',
                unsigned: true,
            })
            const request = requestbuilder(), request2 = requestbuilder()
            const headers1 = signS3Request(credentials, request2)
            expect(request2).toStrictEqual(request)
            expect(headers1).toStrictEqual({
                'x-amz-date': '20190901T084743Z',
                'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
                authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=foo;host;x-amz-content-sha256;x-amz-date, Signature=9368eeb2de103f930a23fbbedd6a937077a63683a92566e561101aead1a51996'
            })

            const headers2 = signS3Request(credentials, request2, { set: true })
            expect(headers1).toStrictEqual(headers2)
            expect(request2).toStrictEqual({
                url: {
                    host: 'example.s3.us-east-1.amazonaws.com:80',
                    pathname: '/folder A',
                    searchParams: new URLSearchParams({ 'list-type': '2' })
                },
                headers: {
                    'foo': 'bar',
                    'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
                    'x-amz-date': '20190901T084743Z',
                    authorization: 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request, SignedHeaders=foo;host;x-amz-content-sha256;x-amz-date, Signature=9368eeb2de103f930a23fbbedd6a937077a63683a92566e561101aead1a51996'
                },
                body: 'should be ignored',
                unsigned: true,
            })
        })
    })

    describe('query based', () => {
        const sortstr = (x: URLSearchParams) => {
            x.sort()
            return x.toString()
        }

        it('basic test', () => {
            const request = {
                url: 'https://examplebucket.s3.amazonaws.com/root//folder A?list-type=2',
                body: 'should be ignored',
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
                url: 'https://examplebucket.s3.amazonaws.com/root//folder%20A?list-type=2&X-Amz-Expires=604800&X-Amz-Date=20190901T084743Z&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20190901%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=2a90f4809bc072d7e58b670b7888dbb932f405f355169ebb9fba2dd27f939153',
                body: 'should be ignored',
            })

            // signing request again should produce same result
            const request3 = { ...request2 }
            const query3 = signS3Request(credentials, request3, { query: true })
            expect(request3).toStrictEqual(request2)
            expect({ ...query2, ...query3 }).toStrictEqual(query2) // query3 must be subset of query2
            const query4 = signS3Request(credentials, request3, { query: true, set: true })
            expect(request3).toStrictEqual(request2)
            expect(query4).toStrictEqual(query3)
        })

        it('allows user to specify X-Amz-Expires', () => {
            const request = {
                url: 'https://examplebucket.s3.amazonaws.com/root//folder A?list-type=2&X-Amz-Expires=2000',
            }
            const request2 = { ...request }
            const query1 = signS3Request(credentials, request2, { query: true })
            expect(request2).toStrictEqual(request)
            expect(query1).toStrictEqual({
                'X-Amz-Date': '20190901T084743Z',
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': 'AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request',
                'X-Amz-SignedHeaders': 'host',
                'X-Amz-Signature': '97f953c9a545dbe43e3d16425aba8f52c764ba72e22d6cda563fddb8b549b95c'
            })

            const query2 = signS3Request(credentials, request2, { query: true, set: true })
            expect(query1).toStrictEqual(query2)
            expect(request2).toStrictEqual({
                url: 'https://examplebucket.s3.amazonaws.com/root//folder%20A?list-type=2&X-Amz-Expires=2000&X-Amz-Date=20190901T084743Z&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20190901%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=97f953c9a545dbe43e3d16425aba8f52c764ba72e22d6cda563fddb8b549b95c'
            })
        })

        it('infers host', () => {
            const requestbuilder = () => ({
                url: {
                    pathname: '/examplebucket/root//folder A',
                    searchParams: new URLSearchParams({ 'list-type': '2' }),
                },
            })
            const request = requestbuilder(), request2 = requestbuilder()
            const query1 = signS3Request(credentials, request2, { query: true })
            expect((request2.url as any).host).toBe('s3.amazonaws.com')
            delete (request2.url as any).host
            expect(request2).toStrictEqual(request)
            expect(query1).toStrictEqual({
                'X-Amz-Expires': '604800',
                'X-Amz-Date': '20190901T084743Z',
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': 'AKIAIOSFODNN7EXAMPLE/20190901/us-east-1/s3/aws4_request',
                'X-Amz-SignedHeaders': 'host',
                'X-Amz-Signature': '92086108c9882d5cf2797746769d7c3ab1bfeb569af3f4aa922a15368f06d84b'
            })

            const query2 = signS3Request(credentials, request2, { query: true, set: true })
            expect(query1).toStrictEqual(query2)
            expect((request2.url as any).host).toBe('s3.amazonaws.com')
            expect((request2.url.pathname)).toBe(request.url.pathname)
            expect(sortstr(request2.url.searchParams)).toBe(sortstr(new URLSearchParams(
                { 'list-type': '2', ...query1 }
            )))
        })

        it('populates url.searchParams if needed', () => {
            const requestbuilder = () => ({
                url: {
                    host: 'examplebucket.s3.us-west-1.amazonaws.com',
                    pathname: '/root//folder A',
                },
                headers: {
                    foo: 'bar',
                }
            })
            const request = requestbuilder(), request2 = requestbuilder()
            const query1 = signS3Request(credentials, request2, { query: true })
            expect(request2).toStrictEqual(request)
            expect(query1).toStrictEqual({
                'X-Amz-Expires': '604800',
                'X-Amz-Date': '20190901T084743Z',
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': 'AKIAIOSFODNN7EXAMPLE/20190901/us-west-1/s3/aws4_request',
                'X-Amz-SignedHeaders': 'foo;host',
                'X-Amz-Signature': '536f36e0569f06f251ed8efc9393d7871d5fbf47d3671fbec16b987ebb05414f'
            })

            const query2 = signS3Request(credentials, request2, { query: true, set: true })
            expect(query1).toStrictEqual(query2)
            expect(request2).toStrictEqual({
                url: {
                    host: 'examplebucket.s3.us-west-1.amazonaws.com',
                    pathname: '/root//folder A',
                    searchParams: new URLSearchParams(query1),
                },
                headers: {
                    foo: 'bar',
                }
            })
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
