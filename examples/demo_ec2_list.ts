/**
 * Demo CLI tool that lists EC2 instances
 */

import { get } from 'https'
import { URLSearchParams } from 'url'
import { signRequest } from '../src/http'
import { toRequestOptions } from '../src/util/request'

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 1) {
    console.error(`Usage: demo_ec2_list.js <region>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    process.exit(1)
}

const credentials = { accessKey, secretKey, serviceName: 'ec2', regionName: args[0] }
const request = {
    url: {
        searchParams: new URLSearchParams({
            Action: 'DescribeInstanceStatus',
            IncludeAllInstances: 'true',
            Version: '2016-11-15',
        }),
    },
}
signRequest(credentials, request, { set: true })

console.log('Sending request:', request)
get(toRequestOptions(request), response => {
    console.log(`Got ${response.statusCode} response:`)
    response.pipe(process.stdout)
})
