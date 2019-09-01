import { signRequest, autoSignRequest } from '../src/http'
import { strictEqual } from 'assert'

{
    const expected = 'AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c'
    const newHeaders = signRequest(
        { accessKey: 'access_test', secretKey: 'secret_test', serviceName: 'ec2', regionName: 'us-east-1' },
        'GET', 'https://ec2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
        {
            'x-amz-date': '20190830T164820Z',
        },
        '',
    )
    strictEqual(newHeaders.authorization, expected)
}

{
    const expected = 'AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c'
    const request = autoSignRequest(
        { accessKey: 'access_test', secretKey: 'secret_test' },
        {
            host: 'ec2.amazonaws.com',
            path: '?Action=DescribeRegions&Version=2013-10-15',
            headers: {
                'x-amz-date': '20190830T164820Z',
            },
        }
    )
    strictEqual(request.headers!.authorization, expected)
}

{
    const expected = 'AWS4-HMAC-SHA256 Credential=access_test/20190830/us-east-1/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=afc0e2557e1c0bc4d8cb15aaf8df57d862fda39caa9cc574215f10987816710c'
    const request = autoSignRequest(
        { accessKey: 'access_test', secretKey: 'secret_test', serviceName: 'ec2' },
        {
            path: '?Action=DescribeRegions&Version=2013-10-15',
            headers: {
                'x-amz-date': '20190830T164820Z',
            },
        }
    )
    strictEqual(request.headers!.host, 'ec2.amazonaws.com')
    strictEqual(request.hostname, 'ec2.amazonaws.com')
    strictEqual(request.headers!.authorization, expected)
}

{
    const expected = 'AWS4-HMAC-SHA256 Credential=access_test/20190830/us-west-2/dynamodb/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=c34b85b7c550eaa329ac72987fb54d77889c5f85e9bf1df213e1ae8db2d5402c'
    const request = autoSignRequest(
        { accessKey: 'access_test', secretKey: 'secret_test' },
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
    strictEqual(request.headers!.authorization, expected)
}
