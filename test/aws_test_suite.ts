import { promisify } from 'util'
import * as fs from 'fs'
import { join, basename } from 'path'
import { strictEqual, notStrictEqual } from 'assert'
const readFile = promisify(fs.readFile)
const readdir = promisify(fs.readdir)

import { autoSignRequest } from '../src/http'

const CREDENTIALS = {
    accessKey: 'AKIDEXAMPLE',
    secretKey: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
    serviceName: 'service',
}

function doTest(input: ParsedRequest, output: string) {
    const hostname = input.headers['Host'][0]
    const request = {...input, hostname}
    autoSignRequest(CREDENTIALS, request, input.body)
    strictEqual(request.headers['authorization'], output)
}

interface ParsedRequest {
    method: string
    path: string
    headers: {[key: string]: string[]}
    body?: string
}

function parseRequest(input: string): ParsedRequest {
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

async function collectTests(tests: string[], root: string, dir: string) {
    const files = await readdir(join(root, dir), { withFileTypes: true })
    const dirs = files.filter(x => x.isDirectory())
    if (!dirs.length) {
        tests.push(dir)
        return
    }
    await Promise.all(dirs.map(x => collectTests(tests, root, join(dir, x.name))))
}

async function main() {
    const testsdir = join(__dirname, 'aws-sig-v4-test-suite')
    const tests: string[] = []
    await collectTests(tests, testsdir, '')
    const passed = [], failed = []

    for (const test of tests.sort()) {
        console.log(`Test: ${test}`)
        const testname = basename(test)
        const testdir = join(testsdir, test)
        const [ input, output ] = await Promise.all(['.req', '.authz']
            .map(x => readFile(join(testdir, testname + x), 'utf-8')))
        const parsedInput = parseRequest(input)

        try {
            doTest(parsedInput, output)
            passed.push(test)
        } catch (err) {
            console.error(((err && err.stack) || err) + '\n')
            failed.push(test)
        }
    }

    console.log(`\nTotal: ${passed.length + failed.length} Failed: ${failed.length}`)
    console.log(failed.length ? `Failed tests:  ${failed.join(', ')}` : 'All tests passed.')
}

main().catch(err => {
    console.error((err && err.stack) || err)
    process.exit(1)
})
