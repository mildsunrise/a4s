import { signRequest, autoSignRequest, getCanonicalURI } from '../src/http'

describe('HTTP signing', () => {

    describe('canonical URI', () => {
        it('returns / for empty string', () =>
            expect(getCanonicalURI('')).toBe('/'))
        it('appends slash if needed', () =>
            expect(getCanonicalURI('a')).toBe('/a'))
        it('appends slash to percent-encoded slash', () =>
            expect(getCanonicalURI('%2f')).toBe('/%252F'))
        it('condenses multiple slashes, «.», «..» and percent-encoded', () =>
            expect(getCanonicalURI('b/////.//..///%2E///%2E///%2E.///.%2E///c')).toBe('/c'))
        it('doesn\'t condense percent-encoded slash', () =>
            expect(getCanonicalURI('//%2f//')).toBe('/%252F/'))
        it('resolves . and .. correctly', () =>
            expect(getCanonicalURI('/a/b/../c/%2E./d')).toBe('/a/d'))
        it('preserves trailing slash', () => {
            expect(getCanonicalURI('../../../c')).toBe('/c')
            expect(getCanonicalURI('../../../c/')).toBe('/c/')
            expect(getCanonicalURI('../../../c/.')).toBe('/c/')
            expect(getCanonicalURI('a/b/..')).toBe('/a/')
            expect(getCanonicalURI('a/%2f')).toBe('/a/%252F')
            expect(getCanonicalURI('a/%2f/.')).toBe('/a/%252F/')
        })
        it('returns uppercase percent-encodes', () =>
            expect(getCanonicalURI('/test%0a')).toBe('/test%250A'))
        it('un-encodes unreserved characters', () =>
            expect(getCanonicalURI('/test%41')).toBe('/testA'))
        it('encodes characters if needed', () =>
            expect(getCanonicalURI('/test\n')).toBe('/test%250A'))
        it('encodes in UTF-8', () =>
            expect(getCanonicalURI('/test😊')).toBe('/test%25F0%259F%2598%258A'))
    })

    describe('signing / autosigning', () => {
        const credentials = { accessKey: 'access_test', secretKey: 'secret_test' }

        it('signs a GET request with only header x-amz-date', () => {
            const newHeaders = signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                'GET', 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
                {
                    'x-amz-date': '20190830T164820Z',
                }
            )
            expect(newHeaders.authorization).toBe('AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c')
        })

        it('auto-signs the request inferring service/region', () => {
            const request = autoSignRequest(
                credentials,
                {
                    host: 'ec2.amazonaws.com',
                    path: '?Action=DescribeRegions&Version=2013-10-15',
                    headers: {
                        'x-amz-date': '20190830T164820Z',
                    },
                },
                ''
            )
            expect(request.headers!.authorization).toBe('AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c')
        })

        it('auto-signs the request inferring the endpoint (without region)', () => {
            const request = autoSignRequest(
                { ...credentials, serviceName: 'ec2' },
                {
                    path: '?Action=DescribeRegions&Version=2013-10-15',
                    headers: {
                        'x-amz-date': '20190830T164820Z',
                    },
                },
                Buffer.from('')
            )
            expect(request.headers!.host).toBe('ec2.amazonaws.com')
            expect(request.hostname).toBe('ec2.amazonaws.com')
            expect(request.headers!.authorization).toBe('AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c')
        })

        it('auto-signs a POST with body', () => {
            const request = autoSignRequest(
                credentials,
                {
                    method: 'POST',
                    host: 'dynamodb.us-west-2.amazonaws.com',
                    headers: {
                        'x-amz-date': '20190830T164820Z',
                        'content-type': 'application/x-amz-json-1.0',
                        'x-amz-target': 'DynamoDB_20120810.CreateTable',
                    },
                },
                '{"KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],"TableName": "TestTable","AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],"ProvisionedThroughput": {"WriteCapacityUnits": 5,"ReadCapacityUnits": 5}}',
            )
            expect(request.headers!.authorization).toBe('AWS4-HMAC-SHA256 Credential=access_test/20190830/us-west-2/dynamodb/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=c34b85b7c550eaa329ac72987fb54d77889c5f85e9bf1df213e1ae8db2d5402c')
        })
    })

})
