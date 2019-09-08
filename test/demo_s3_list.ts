/**
 * Demo CLI tool that makes a LIST request to a bucket.
 */

import { URL } from 'url'
import { get } from 'https'
import { signS3Request, SignedS3Request } from '../src/s3'

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 1) {
    console.error(`Usage: demo_s3_list.js <URL>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    process.exit(1)
}

const url = new URL(args[0])
url.search = 'list-type=2'
const request: SignedS3Request = { url }
signS3Request({ accessKey, secretKey }, request, { set: true })

console.log('Sending request:', request)
get(request.url as URL, request, response => {
    console.log(`Got ${response.statusCode} response:`)
    response.pipe(process.stdout)
})
