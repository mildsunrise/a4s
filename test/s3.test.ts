import { signS3Policy, signS3Request } from '../src/s3'

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
