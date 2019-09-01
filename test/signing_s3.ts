import { signPolicy } from '../src/s3'
import { strictEqual, deepStrictEqual } from 'assert'

{
    const credentials = {
        accessKey: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        regionName: 'eu-west-2',
    }
    const params = signPolicy(credentials,
        {
            expires: new Date(1567327687881).toISOString(),
        },
        { timestamp: new Date(1567327663238) }
    )
    const policy = JSON.parse(Buffer.from(params.policy!, 'base64').toString())
    deepStrictEqual(policy, {
        expires: '2019-09-01T08:48:07.881Z',
        conditions: [
            { 'x-amz-date': '20190901T084743Z' },
            { 'x-amz-algorithm': 'AWS4-HMAC-SHA256' },
            { 'x-amz-credential': 'AKIAIOSFODNN7EXAMPLE/20190901/eu-west-2/s3/aws4_request' },
        ]
    })
    deepStrictEqual(params, {
        policy: 'eyJleHBpcmVzIjoiMjAxOS0wOS0wMVQwODo0ODowNy44ODFaIiwiY29uZGl0aW9ucyI6W3sieC1hbXotZGF0ZSI6IjIwMTkwOTAxVDA4NDc0M1oifSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lBSU9TRk9ETk43RVhBTVBMRS8yMDE5MDkwMS9ldS13ZXN0LTIvczMvYXdzNF9yZXF1ZXN0In1dfQ==',
        'x-amz-date': '20190901T084743Z',
        'x-amz-algorithm': 'AWS4-HMAC-SHA256',
        'x-amz-credential': 'AKIAIOSFODNN7EXAMPLE/20190901/eu-west-2/s3/aws4_request',
        'x-amz-signature': 'c3ce6aeeaa95c11abccd1689a83bba274e28c83b4be080978e7863108bd6edf0',
    })

    const params2 = signPolicy(credentials,
        {
            expires: new Date(1567327687881).toISOString(),
            conditions: [],
        },
        { timestamp: '20190901T084743Z' }
    )
    deepStrictEqual(params2, params)
}
