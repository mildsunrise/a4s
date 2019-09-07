/**
 * Utilities to normalize and work with headers.
 */

const normalizeValue = (value: string | string[] | number | undefined) =>
    value instanceof Array ? value.join(',') : value + ''

/**
 * Find the name and value of a header in an unnormalized headers object.
 *
 * @param headers Headers object
 * @param name Name of header to find, **must be lowercase**
 * @returns Array with name and value (as string); if not found
 * then [name, undefined] will be returned.
 */
export function getHeader(
    headers: {[key: string]: string | string[] | number | undefined} | undefined,
    name: string,
): [ string, string | undefined ] {
    if (headers) {
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === name) {
                return [ key, normalizeValue(headers[key]) ]
            }
        }
    }
    return [ name, undefined ]
}
