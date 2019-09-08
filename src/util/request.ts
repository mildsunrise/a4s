/**
 * Utilities to normalize and work with requests and headers.
 */

import { SignedRequest } from '../http'
import { RequestOptions } from 'http'
import { URL } from 'url';

const normalizeValue = (value: string | string[] | number | undefined) =>
    value instanceof Array ? value.join(',') : value + ''

/**
 * Find the name and value of a header in an unnormalized headers object.
 *
 * @param headers Headers object
 * @param name Name of header to find
 * @returns Array with name and value (as string); if not found
 * then [name, undefined] will be returned.
 */
export function getHeader(
    headers: {[key: string]: string | string[] | number | undefined} | undefined,
    name: string,
): [ string, string | undefined ] {
    name = name.toLowerCase()
    if (headers) {
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === name) {
                return [ key, normalizeValue(headers[key]) ]
            }
        }
    }
    return [ name, undefined ]
}

export function toRequestOptions(
    request: SignedRequest
): RequestOptions {
    let { method, url, headers } = request
    url = typeof url === 'string' ? new URL(url) : url
    const { host, pathname, searchParams } = url
    const query = searchParams && searchParams.toString()
    const path = (pathname || '/') + (query ? '?' + query : '')
    return { method, headers, host, path }
}
