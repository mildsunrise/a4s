/**
 * Demo CLI tool that makes a LIST request to a bucket.
 */

import { URLSearchParams } from 'url'
import { get } from 'https'
import { signS3Request } from '../src/s3'
import { toRequestOptions } from '../src/util/request'
import { formatHost } from '../src/util/endpoint'

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 2) {
    console.error(`Usage: demo_s3_list.js <bucket> <region>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    process.exit(1)
}

const [ bucket, regionName ] = args
const request = {
    url: {
        host: `${bucket}.${formatHost('s3', regionName)}`,
        searchParams: new URLSearchParams({ 'list-type': '2' }),
    }
}
signS3Request({ accessKey, secretKey }, request, { set: true })

console.log('Sending request:', request)
get(toRequestOptions(request), response => {
    console.log(`Got ${response.statusCode} response:`)
    response.pipe(process.stdout)
})
