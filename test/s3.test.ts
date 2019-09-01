import { signPolicy } from '../src/s3'

describe('S3 signing', () => {
    const credentials = {
        accessKey: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        regionName: 'eu-west-2',
    }

    describe('Authorization-based', () => {

    })

    describe('Authorization-based payload streaming', () => {

    })

    describe('query-based', () => {

    })

    describe('POST form based', () => {
        it('should sign a policy correctly', () => {
            const params = signPolicy(credentials,
                {
                    expires: new Date(1567327687881).toISOString(),
                },
                { timestamp: new Date(1567327663238) }
            )
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
            const params = signPolicy(
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