/**
 * This runs an adapted version of the spec that is used
 * in aws-sdk for signing. Many tests have been removed:
 * 
 *  - Ignoring an existing Authorization header when signing
 *  - Ignoring X-Amzn-Trace-Id
 *  - Hoisting certain headers to query parameters, when
 *    signing S3 through query
 *
 */
import { getCanonical, signRequest, autoSignRequest, getCanonicalHeaders, getCanonicalQuery, getCanonicalURI } from '../src/http'
import { RequestOptions } from 'http'
import { formatTimestamp, formatDate } from '../src/core';

const buildRequest = (): RequestOptions & {
    body: string, endpoint: any, region: string, headers: {[key: string]: string}
} => ({
    method: 'POST',
    path: '/',
    headers: {
        //'User-Agent': 'aws-sdk-nodejs/2.519.0 linux/v12.6.0',
        //'Content-Type': 'application/x-amz-json-1.0',
        'X-Amz-Target': 'DynamoDB_20111205.ListTables',
        'X-Amz-Content-Sha256': '3128b8d4f3108b3e1677a38eb468d1c6dec926a58eaea235d034b9c71c3864d4',
        //'Content-Length': '34',
        Host: 'localhost',
        'X-Amz-Date': '20310430T201613Z',
        //Authorization: 'AWS4-HMAC-SHA256 Credential=AKIAXGQFHVFCKUIN2IOF/20190901/region/dynamodb/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-target, Signature=fe8113da52a150c44732abb169bbe3dfd37df309fec186a149f8e4d82aa707b5',
        'X-Amz-User-Agent': 'aws-sdk-js/0.1',
        'X-Amz-Security-Token': 'session',
    },
    body: '{"ExclusiveStartTableName":"bår"}',
    endpoint: {
        protocol: 'https:',
        host: 'localhost',
        port: 443,
        hostname: 'localhost',
        pathname: '/',
        path: '/',
        href: 'https://localhost/',
    },
    region: 'region',
    //_userAgent: 'aws-sdk-nodejs/2.519.0 linux/v12.6.0',
})

const creds = {
    accessKey: 'akid',
    secretKey: 'secret',
}
const fullCreds = {
    ...creds,
    serviceName: 'dynamodb',
    regionName: 'region',
}

const date = new Date(1935346573456)
const signature = '31fac5ed29db737fbcafac527470ca6d9283283197c5e6e94ea40ddcec14a9c1'
const authorization = `AWS4-HMAC-SHA256 Credential=akid/20310430/region/dynamodb/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-target;x-amz-user-agent, Signature=${signature}`
const datetime = '20310430T201613Z'

describe('SDK spec, HTTP signing', () => {

    describe('general', function() {
        it('can accept an options object', function() {
            let options: object = { no: true }
            const request = buildRequest()
            autoSignRequest(fullCreds, request, request.body, options)
            expect(request.headers.authorization).toBe(authorization)
        })
        it('should generate proper signature', function() {
            const request = buildRequest()
            autoSignRequest(fullCreds, request, request.body)
            expect(request.headers.authorization).toBe(authorization)
        })
        // it('should not compute SHA 256 checksum more than once')
        it('should generate timestamp correctly', () => {
            expect(formatTimestamp(date)).toBe(datetime)
            expect(formatDate(date)).toBe(datetime.substring(0, 8))
        })
    })

    /*describe('stringToSign', function() {
        it('should sign correctly generated input string', function() {
            expect(signer.stringToSign(datetime)).to.equal('AWS4-HMAC-SHA256\n' + datetime + '\n' + '20310430/region/dynamodb/aws4_request\n' + signer.hexEncodedHash(signer.canonicalString()))
        })
    })*/

    describe('canonical url / query', function() {
        it('sorts the search string', function() {
            const cq = getCanonicalQuery({
                query: 'foo',
                cursor: 'initial',
                queryOptions: '{}'
            })
            expect(cq).toBe('cursor=initial&query=foo&queryOptions=%7B%7D')
        })
        
        it('double URI encodes paths for non S3 services', function() {
            const cp = getCanonicalURI('/identitypools/id/identities/a:b:c/datasets')
            expect(cp).toBe('/identitypools/id/identities/a%253Ab%253Ac/datasets')
        })
        
        it('does not double encode path for S3', function() {
            const cp = getCanonicalURI('/a:b:c', { onlyEncodeOnce: true })
            expect(cp).toBe('/a%3Ab%3Ac')
        })
    })

    describe('canonical headers', function() {
        it('should return headers', function() {
            const ch = getCanonicalHeaders(buildRequest().headers)[0]
            expect(ch).toBe(['host:localhost', 'x-amz-content-sha256:3128b8d4f3108b3e1677a38eb468d1c6dec926a58eaea235d034b9c71c3864d4', 'x-amz-date:' + datetime, 'x-amz-security-token:session', 'x-amz-target:DynamoDB_20111205.ListTables', 'x-amz-user-agent:aws-sdk-js/0.1'].join('\n') + '\n')
        })
        
        it('should lowercase all header names (not values)', function() {
            const headers = {
                'FOO': 'BAR'
            }
            expect(getCanonicalHeaders(headers)[0]).toBe('foo:BAR\n')
        })
        
        it('should sort headers by key', function() {
            const headers = {
                abc: 'a',
                bca: 'b',
                Qux: 'c',
                bar: 'd'
            }
            expect(getCanonicalHeaders(headers)[0]).toBe('abc:a\nbar:d\nbca:b\nqux:c\n')
        })
        
        it('should compact multiple spaces in keys/values to a single space', function() {
            const headers = {
                'Header': 'Value     with  Multiple   \t spaces'
            }
            expect(getCanonicalHeaders(headers)[0]).toBe('header:Value with Multiple spaces\n')
        })
        
        it('should strip starting and end of line spaces', function() {
            const headers = {
                'Header': ' \t   Value  \t  '
            }
            expect(getCanonicalHeaders(headers)[0]).toBe('header:Value\n')
        })
        
    })

    /*describe('presigned urls', function() {
        it('hoists content-type to the query string', function() {
            var req
            req = new AWS.S3().putObject({
                Bucket: 'bucket',
                Key: 'key',
                ContentType: 'text/plain'
            }).build()
            signer = new AWS.Signers.V4(req.httpRequest, 's3')
            signer.updateForPresigned({}, '')
            expect(signer.canonicalString().split('\n')[2]).to.contain('Content-Type=text%2Fplain')
        })
        it('hoists content-md5 to the query string', function() {
            var req
            req = new AWS.S3().putObject({
                Bucket: 'bucket',
                Key: 'key',
                ContentMD5: 'foobar=='
            }).build()
            signer = new AWS.Signers.V4(req.httpRequest, 's3')
            signer.updateForPresigned({}, '')
            expect(signer.canonicalString().split('\n')[2]).to.contain('Content-MD5=foobar%3D%3D')
        })
    })*/

})
