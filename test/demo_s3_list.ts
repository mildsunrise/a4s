/**
 * Demo CLI tool that presigns the passed S3 URL.
 */

import { URL } from 'url'
import { get } from 'https'
import { autoSignRequestHeader } from '../src/s3'

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 1) {
    console.error(`Usage: demo_s3_list.js <URL>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    process.exit(1)
}

const url = new URL(args[0])
const request = autoSignRequestHeader({ accessKey, secretKey }, {
    host: url.host,
    path: `${url.pathname}?list-type=2`,
})

console.log('Sending request:', request)
get(request, response => {
    console.log(`Got ${response.statusCode} response:`)
    response.pipe(process.stdout)
})
