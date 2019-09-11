/**
 * Demo CLI tool that uploads a file to S3 using chunked payload
 * streaming, with 16kB chunks.
 */

import { URL } from 'url'
import * as https from 'https'
import { pipeline } from 'stream'
import { statSync, createReadStream } from 'fs'
import { createS3PayloadSigner } from '../src/s3_chunked'

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 2) {
    console.error(`Usage: demo_s3_upload.js <URL> <file>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    process.exit(1)
}

const url = new URL(args[0])
const fileSize = statSync(args[1]).size
const input = createReadStream(args[1])

const request = { method: 'PUT', url }
const { signer } = createS3PayloadSigner(
    { accessKey, secretKey }, request, fileSize, 64 * 1024, { set: true })

console.log('Sending request:', request)
const output = https.request(request.url, request, response => {
    console.log(`Got ${response.statusCode} response:`)
    response.pipe(process.stdout)
})

pipeline(input, signer, output, (err) => {
    if (err) {
        throw err
    }
    console.log('Upload sent.')
})
