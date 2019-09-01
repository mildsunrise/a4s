/**
 * Starts up a demo webserver that lets visitors upload files to
 * a private S3 bucket, using {{signPolicy}}.
 */

import { parse } from 'url'
import { createServer, IncomingMessage, ServerResponse } from 'http'
import { signPolicy } from '../src/signing_s3'
import { randomBytes } from 'crypto'

const accessKey = process.env.AWS_ACCESS_KEY_ID!
const secretKey = process.env.AWS_SECRET_ACCESS_KEY!
const args = process.argv.slice(2)
if (!accessKey || !secretKey || args.length !== 2) {
    console.error(`Usage: demo_s3_post.js <bucket name> <region>`)
    console.error('Please make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set')
    process.exit(1)
}

const [ bucket, regionName ] = args
const credentials = { accessKey, secretKey, regionName }

createServer((req, res) => {
    const { pathname, query } = parse(req.url || '', true)
    if (pathname === '/') {
        const key = `uploads/${randomBytes(3).toString('hex')}`
        renderUploadForm(key, req, res)
    } else if (pathname === '/success') {
        res.end(`Uploaded successfully!\nEtag: ${query.etag}`)
    } else {
        res.end('Not found')
    }
}).listen(process.env.PORT || 8080)


function renderUploadForm(key: string, req: IncomingMessage, res: ServerResponse) {
    let params: {[key: string]: string} = {
        success_action_redirect: `http://${req.headers.host}/success`,
        key: key + '/${filename}',
    }

    // Sign a policy and add the resulting parameters
    const policy = {
        expiration: new Date(Date.now() + 30 * 60e3).toISOString(), // valid for 30m
        conditions: [
            { bucket },
            { success_action_redirect: params.success_action_redirect },
            [ 'starts-with', '$key', key + '/' ],
            [ 'content-length-range', 0, 2*1024*1024 ],
        ]
    }
    params = { ...params, ...signPolicy(credentials, policy) }

    // Build the form's HTML
    const paramsHtml = Object.keys(params).map(k =>
        `<input type="hidden" name="${escape(k)}" value="${escape(params[k])}">`).join('')
    const html = `
        <!doctype html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>Upload file</title>
            </head>
            <body>
                <h1>Upload file</h1>
                <p>Use this form to upload a file to S3 (max 2MB). <br>
                   The file will be uploaded at: <code>${escape(key)}</code></p>
                <form action="http://${escape(bucket)}.s3.amazonaws.com/"
                      method="post" enctype="multipart/form-data">
                    ${paramsHtml}
                    <input id="chooser" type="file" name="file">
                </form>
                <script> setTimeout(function () {
                    document.getElementById('chooser').addEventListener('change',
                        function () { this.value && this.form.submit() })
                }, 300); </script>
            </body>
        </html>
    `

    // Send it
    res.setHeader('Content-Type', 'text/html')
    res.end(html)
}

const escape = (x: string) => x.replace(/&/g, '&amp;')
    .replace(/>/g, '&gt;').replace(/</g, '&lt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&apos;')
