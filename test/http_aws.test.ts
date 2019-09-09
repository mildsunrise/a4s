/**
 * This runs the test suite provided by AWS. The test suite
 * contains numerous errors which had to be fixed, and two
 * tests were deleted.
 * 
 * https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html
 */

import { promisify } from 'util'
import { URLSearchParams } from 'url'
import * as fs from 'fs'
import { join, basename } from 'path'
const readFile = promisify(fs.readFile)

import { signRequest, getCanonical, getCanonicalHeaders, signRequestRaw } from '../src/http'

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

            const headers2 = { ...input.headers }
            const query2 = new URLSearchParams(query)
            const result1 = signRequestRaw({ ...CREDENTIALS, regionName: 'us-east-1' },
                input.method, pathname, query2, headers2, input.body)
            expect(headers2).toStrictEqual(input.headers)
            expect(query2.toString()).toBe(new URLSearchParams(query).toString())
            expect(result1)
            expect(result1['authorization']).toBe(expAuthorization)

            const host = input.headers['Host'][0]
            const request = { ...input, url: `https://${host}${input.path}` }
            const request2 = JSON.parse(JSON.stringify(request))
            expect(request2).toStrictEqual(request)
            const result2 = signRequest(CREDENTIALS, request2)
            expect(request2).toStrictEqual(request)
            expect(result2).toStrictEqual(result1)
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

    function parseRequest(input: string): { method: string, path: string, headers: {[key: string]: string[]}, body?: string } {
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
        let result = { method, path, headers }
        return body ? { ...result, body } : result
    }
})
