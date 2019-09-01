import { signRequest, autoSignRequest } from '../src/http'

describe('HTTP signing', () => {
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
