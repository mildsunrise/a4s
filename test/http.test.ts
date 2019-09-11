import { URLSearchParams } from 'url'
import { signRequest, getCanonicalURI, SignedRequest, getCanonicalHeaders, parseAuthorization } from '../src/http'

const oDate = Date
const date = jest.spyOn(global, 'Date').mockImplementation(((s: any) => {
    return s ? new oDate(s) : new oDate(1567282344069)
}) as any)

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

    describe('canonical headers', () => {
        it('throws if there are duplicate header keys', () => {
            expect(() => getCanonicalHeaders({
                'a': 'foo',
                'b': 'bar',
                'test': 34,
                'tEst': '12',
            })).toThrow()
        })
    })

    describe('Authorization parsing', () => {
        it('basic test', () => {
            expect(parseAuthorization('ALGORITHM-TEST2 Signature=41, SignedHeaders=foo, Credential=bar'))
                .toStrictEqual({
                    algorithm: 'ALGORITHM-TEST2',
                    signature: Buffer.from('A'),
                    credential: 'bar',
                    signedHeaders: 'foo'
                })
        })

        it('ignores whitespace', () => {
            expect(parseAuthorization('  ALGORITHM    Signature=41 ,SignedHeaders= hey you  , Credential=  '))
                .toStrictEqual({
                    algorithm: 'ALGORITHM',
                    signedHeaders: ' hey you',
                    signature: Buffer.from('A'),
                    credential: ''
                })
        })

        it("throws if there's invalid syntax", () => {
            expect(() => parseAuthorization('ALGORITHM')).toThrow()
            expect(() => parseAuthorization('ALGORITHM ')).toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=40, SignedHeaders=a, Credential')).toThrow()
        })

        it('for duplicate fields, last one wins', () => {
            expect(parseAuthorization('ALGORITHM Signature=41, SignedHeaders=m=a, Credential=a, Credential=b, Credential=c, credential=d'))
                .toStrictEqual({
                    algorithm: 'ALGORITHM',
                    signedHeaders: 'm=a',
                    signature: Buffer.from('A'),
                    credential: 'c',
                })
        })

        it('throws if there are missing fields', () => {
            expect(() => parseAuthorization('ALGORITHM Signature=40, SignedHeaders=m=a')).toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=40, Credential=b')).toThrow()

            expect(() => parseAuthorization('ALGORITHM Signature=40, SignedHeaders=m=a, Credential=b')).not.toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=40, SignedHeaders=m=a, Credential=b, credential=2')).not.toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=40, SignedHeaders=m=a, credential=2')).toThrow()
        })

        it("throws if Signature isn't valid lowercase hexdump", () => {
            expect(() => parseAuthorization('ALGORITHM Signature=40, SignedHeaders=a, Credential=b')).not.toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=4a, SignedHeaders=a, Credential=b')).not.toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=4A, SignedHeaders=a, Credential=b')).toThrow()

            expect(() => parseAuthorization('ALGORITHM Signature=405, SignedHeaders=a, Credential=b')).toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=4050, SignedHeaders=a, Credential=b')).not.toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=40h0, SignedHeaders=a, Credential=b')).toThrow()
            expect(() => parseAuthorization('ALGORITHM Signature=40 50, SignedHeaders=a, Credential=b')).toThrow()
        })
    })

    describe('signing', () => {
        const credentials = { accessKey: 'access_test', secretKey: 'secret_test' }

        it('signs a GET request with only header x-amz-date', () => {
            const requester = () => ({
                url: 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
                headers: {
                    'x-amz-date': '20190830T164820Z',
                },
            })
            const request1 = requester(), request2 = requester()
            const newHeaders = signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                request2
            )
            expect(request1).toStrictEqual(request2)
            expect(newHeaders.authorization).toBe('AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c')
        })

        it('signs a request using query parameters', () => {
            const requester = () => ({
                method: 'PUT',
                url: 'https://ec2.amazonaws.com?X-Amz-Date=20190830T164820Z&Action=DescribeRegions&Version=2013-10-15',
            })
            const request1 = requester(), request2 = requester()
            const query = signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                request2,
                { query: true }
            )
            expect(request1).toStrictEqual(request2)
            expect(query).toStrictEqual({
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': 'access_test/20190830/us-east-1/ec2/aws4_request',
                'X-Amz-SignedHeaders': 'host',
                'X-Amz-Signature': 'd935014135f10370b9612a0db8877ee51809544c08acd74a22647be1764cc345'
            })
        })

        it('auto-signs a request using query parameters', () => {
            const request = {
                method: 'PUT',
                url: 'https://ec2.amazonaws.com?X-Amz-Date=20190830T164820Z&Action=DescribeRegions&Version=2013-10-15',
            }
            const query = signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                request,
                { query: true, set: true }
            )
            expect(query).toStrictEqual({
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': 'access_test/20190830/us-east-1/ec2/aws4_request',
                'X-Amz-SignedHeaders': 'host',
                'X-Amz-Signature': 'd935014135f10370b9612a0db8877ee51809544c08acd74a22647be1764cc345'
            })
            expect(request).toStrictEqual({
                method: 'PUT',
                url: 'https://ec2.amazonaws.com/?X-Amz-Date=20190830T164820Z&Action=DescribeRegions&Version=2013-10-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=access_test%2F20190830%2Fus-east-1%2Fec2%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=d935014135f10370b9612a0db8877ee51809544c08acd74a22647be1764cc345'
            })
        })

        it('populates url.searchParams if needed', () => {
            const sorted = (x: any) => {
                x.sort()
                return x
            }
            const request = {
                method: 'PUT',
                url: {},
            }
            const query = signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                request,
                { query: true, set: true }
            )
            expect(query).toStrictEqual({
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': 'access_test/20190831/us-east-1/ec2/aws4_request',
                'X-Amz-SignedHeaders': 'host',
                'X-Amz-Date': '20190831T201224Z',
                'X-Amz-Signature': 'bfd068f0e69d31f06a04b25173b6d3ff53325c8ae6f830779adc71de27e54bd8'
            })
            expect((request.url as any).host).toBe('ec2.us-east-1.amazonaws.com')
            expect((request.url as any).pathname).toBe(undefined)
            expect(sorted((request.url as any).searchParams).toString()).toBe(sorted(new URLSearchParams(query)).toString())
        })

        it('auto-signs the request inferring service/region', () => {
            const request: SignedRequest = {
                url: {
                    host: 'ec2.amazonaws.com',
                    searchParams: new URLSearchParams({
                        Action: 'DescribeRegions', Version: '2013-10-15',
                    }),
                },
                headers: {
                    'x-amz-date': '20190830T164820Z',
                },
            }
            signRequest(credentials, request, { set: true })
            expect(request.headers!.authorization).toBe('AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c')
        })

        it('auto-signs the request inferring the endpoint (without region)', () => {
            const request: SignedRequest = {
                url: { 
                    searchParams: new URLSearchParams({
                        Action: 'DescribeRegions', Version: '2013-10-15',
                    }),
                },
                headers: {
                    'x-amz-date': '20190830T164820Z',
                },
            }
            signRequest({ ...credentials, serviceName: 'ec2' }, request, { set: true })
            expect((request.url as any).host).toBe('ec2.amazonaws.com')
            expect(request.headers!.authorization).toBe('AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c')
        })

        it('signs a POST with body', () => {
            const result = signRequest(
                credentials,
                {
                    method: 'POST',
                    url: { host: 'dynamodb.us-west-2.amazonaws.com' },
                    headers: {
                        'x-amz-date': '20190830T164820Z',
                        'content-type': 'application/x-amz-json-1.0',
                        'x-amz-target': 'DynamoDB_20120810.CreateTable',
                    },
                    body: '{"KeySchema": [{"KeyType": "HASH","AttributeName": "Id"}],"TableName": "TestTable","AttributeDefinitions": [{"AttributeName": "Id","AttributeType": "S"}],"ProvisionedThroughput": {"WriteCapacityUnits": 5,"ReadCapacityUnits": 5}}',
                }
            )
            expect(result.authorization).toBe('AWS4-HMAC-SHA256 Credential=access_test/20190830/us-west-2/dynamodb/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=c34b85b7c550eaa329ac72987fb54d77889c5f85e9bf1df213e1ae8db2d5402c')
        })

        it('calls Date.now() once to generate signature, and returns / sets it', () => {
            date.mockClear()
            const query = signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                {
                    method: 'PUT',
                    url: 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
                },
                { query: true }
            )
            expect(date).toHaveBeenCalledTimes(1)
            expect(query).toStrictEqual({
                'X-Amz-Date': '20190831T201224Z',
                'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
                'X-Amz-Credential': 'access_test/20190831/us-east-1/ec2/aws4_request',
                'X-Amz-SignedHeaders': 'host',
                'X-Amz-Signature': '814c413ad3ec5456fca403ceb96ae3c97ef467e401660080d888a2101f5ec903'
            })

            const rquery = {
                method: 'PUT',
                url: 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
            }
            date.mockClear()
            signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                rquery,
                { query: true, set: true }
            )
            expect(date).toHaveBeenCalledTimes(1)
            expect(rquery).toStrictEqual({
                method: 'PUT',
                url: 'https://ec2.amazonaws.com/?Action=DescribeRegions&Version=2013-10-15&X-Amz-Date=20190831T201224Z&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=access_test%2F20190831%2Fus-east-1%2Fec2%2Faws4_request&X-Amz-SignedHeaders=host&X-Amz-Signature=814c413ad3ec5456fca403ceb96ae3c97ef467e401660080d888a2101f5ec903'
            })

            date.mockClear()
            const headers = signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                {
                    method: 'PUT',
                    url: 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
                },
                {}
            )
            expect(date).toHaveBeenCalledTimes(1)
            expect(headers).toStrictEqual({
                'x-amz-date': '20190831T201224Z',
                authorization: 'AWS4-HMAC-SHA256 Credential=access_test/20190831/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=e4cd083abe3ddd69c1548ec1466784ff59d8dfe4e9004c6d2fb2bbc197d6773b'
            })

            const rheaders = {
                method: 'PUT',
                url: 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
            }
            date.mockClear()
            signRequest(
                { ...credentials, serviceName: 'ec2', regionName: 'us-east-1' },
                rheaders,
                { set: true }
            )
            expect(date).toHaveBeenCalledTimes(1)
            expect(rheaders).toStrictEqual({
                method: 'PUT',
                url: 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
                headers: {
                    'x-amz-date': '20190831T201224Z',
                    authorization: 'AWS4-HMAC-SHA256 Credential=access_test/20190831/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=e4cd083abe3ddd69c1548ec1466784ff59d8dfe4e9004c6d2fb2bbc197d6773b'
                }
            })
        })

        it('throws if neither url.host nor serviceName is present', () => {
            expect(() => {
                signRequest(
                    credentials,
                    { url: { pathname: '/a', searchParams: new URLSearchParams() } }
                )
            }).toThrow()
        })
    })

})
