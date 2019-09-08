/**
 * This runs the test suite provided by AWS. The test suite
 * contains numerous errors which had to be fixed, and two
 * tests were deleted.
 * 
 * https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html
 */

import { promisify } from 'util'
import * as fs from 'fs'
import { join, basename } from 'path'
const readFile = promisify(fs.readFile)

import { signRequest, getCanonical, getCanonicalHeaders } from '../src/http'

describe('AWS test suite', () => {
    const CREDENTIALS = {
        accessKey: 'AKIDEXAMPLE',
        secretKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        serviceName: 'service',
    }

    const testsdir = join(__dirname, 'aws-sig-v4-test-suite')
    const tests: string[] = []
    collectTests(tests, testsdir, '')
    for (const test of tests.sort()) {
        it(`passes test ${test}`, async () => {
            const testname = basename(test)
            const testdir = join(testsdir, test)        
            const files = await Promise.all(['.req', '.creq', '.authz']
                .map(x => readFile(join(testdir, testname + x), 'utf-8')))
            const input = parseRequest(files[0])
            const [ expCanonical, expAuthorization ] = files.slice(1)

            const [ pathname, query ] = /^([^?]*)(\?.*)?$/.exec(input.path)!.slice(1)
            const canonical = getCanonical(input.method, pathname, query || '',
                getCanonicalHeaders(input.headers), input.body)
            expect(canonical).toBe(expCanonical)

            const host = input.headers['Host'][0]
            const request = { ...input, url: `https://${host}${input.path}` }
            const result = signRequest(CREDENTIALS, request)
            expect(result['authorization']).toBe(expAuthorization)
        })
    }

    function collectTests(tests: string[], root: string, dir: string) {
        const files = fs.readdirSync(join(root, dir), { withFileTypes: true })
        const dirs = files.filter(x => x.isDirectory())
        if (!dirs.length) {
            tests.push(dir)
            return
        }
        dirs.forEach(x => collectTests(tests, root, join(dir, x.name)))
    }        

    function parseRequest(input: string) {
        const re = /^([A-Z]+) ([^\n]+) HTTP\/1\.1((\n[^:\n]+:[^\n]*(\n[^\n:]+)*)*)(\n\n(.*))?$/s
        const match = re.exec(input)
        if (!match) {
            throw new Error("Couldn't parse input request")
        }
        const [ method, path, rawHeaders, body ] = [ match[1], match[2], match[3], match[7] ]
        const headers: {[key: string]: string[]} = {}
        if (rawHeaders) {
            let buffer = rawHeaders.substring(1)
            while (buffer.length) {
                const match = /^([^:\n]+):([^\n]*([^:\n]*(\n|$))+)/.exec(buffer)!
                const [ name, value ] = [ match[1], match[2] ]
                if (!{}.hasOwnProperty.call(headers, name)) {
                    headers[name] = []
                }
                headers[name] = headers[name].concat(value.trimRight().split('\n'))
                buffer = buffer.substring(match[0].length)
            }
        }
        return { method, path, headers, body }
    }
})
