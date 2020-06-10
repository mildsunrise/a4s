/**
 * Simple reverse proxy that will blindly sign any
 * requests it receives and forward them to S3
 */

import { URL } from 'url'
import { pipeline } from 'stream'
import { once } from 'events'
import { createServer } from 'http'
import { request, Agent } from 'https'
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
const s3Host = `${bucket}.${formatHost('s3', regionName)}`

const baseOptions = {
    agent: new Agent({
        keepAlive: true,
        maxFreeSockets: 16,
    }),
}

createServer((req, res) => {
    const { method, headers, url } = req

    const s3Request = {
        method,
        url: new URL(url!, `http://${headers.host}`),
        headers: { ...headers },
        unsigned: true,
    }
    delete s3Request.headers.host
    delete s3Request.headers.connection
    s3Request.url.protocol = 'https:'
    s3Request.url.port = ''
    s3Request.url.host = s3Host
    signS3Request({ accessKey, secretKey }, s3Request, { set: true })

    const oreq = request({ ...baseOptions, ...toRequestOptions(s3Request) })
    pipeline(req, oreq, () => {})
    once(oreq, 'response').then(([ores]) => {
        delete ores.headers.connection
        res.writeHead(ores.statusCode, ores.headers)
        pipeline(ores, res, () => {})
    }, err => {
        res.statusCode = 502
        res.end(`Couldn't get a response from S3:\n${err.stack}\n`)
    })
}).listen(process.env.PORT || 8080)
