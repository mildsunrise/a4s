/**
 * Demo CLI tool that generates a presigned GET URL for a bucket object.
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

const credentials = { accessKey, secretKey, regionName, serviceName: 's3' }
const host = `${bucket}.${formatHost('s3', regionName)}`
const pathname = encodeURI(key[0] === '/' ? key : `/${key}`)
const url = { host, pathname }
signS3Request(credentials, { url }, { query: true, set: true })

console.log('Presigned URL:', toURL(url))
