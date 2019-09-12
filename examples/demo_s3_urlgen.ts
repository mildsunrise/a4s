/**
 * Demo CLI tool that generates presigned GET URLs for a bucket object,
 * in both path and domain form.
 */

import { signS3Request } from '../src/s3'
import { formatHost } from '../src/util/endpoint'
import { toURL } from '../src/util/request'

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 3) {
    console.error(`Usage: demo_s3_urlgen.js <bucket name> <region> <object>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    process.exit(1)
}

const [ bucket, regionName, key ] = args
const credentials = { accessKey, secretKey, regionName }

const url1 = { pathname: `/${bucket}/${key}` }
signS3Request(credentials, { url: url1 }, { query: true, set: true })
console.log('Presigned URL (path form):\n' + toURL(url1) + '\n')

const host = `${bucket}.${formatHost('s3', regionName)}`
const url2 = { host, pathname: `/${key}` }
signS3Request(credentials, { url: url2 }, { query: true, set: true })
console.log('Presigned URL (domain form):\n' + toURL(url2) + '\n')
