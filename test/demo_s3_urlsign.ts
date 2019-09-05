/**
 * Demo CLI tool that presigns the passed S3 URL.
 */

import { signURL } from '../src/s3'

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 1) {
    console.error(`Usage: demo_s3_urlsign.js <URL>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    process.exit(1)
}

console.log('Presigned URL:', signURL({ accessKey, secretKey }, args[0]))
