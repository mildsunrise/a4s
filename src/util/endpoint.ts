/**
 * Utilities for inferring service / region from endpoints (hosts)
 * and vice versa.
 * @module
 */

/** Default region for AWS requests */
export const DEFAULT_REGION = 'us-east-1'

export const ENDPOINT_OVERRIDES: {[key: string]: string} = {
    ses: 'email',
}

export const SERVICE_OVERRIDES: {[key: string]: string} = {
    email: 'ses',
    transcribestreaming: 'transcribe',
}

const isRegion = (x: string) => /^[a-z]{1,3}-[a-z]+-\d{1,2}$/i.test(x)

/**
 * Infer serviceName / regionName from an endpoint host, for signing.
 * The port (if any) will be ignored.
 * Note: If host doesn't specify a region *and* there's a subdomain,
 * this may not work.
 */
export function parseHost(host: string) {
    // Match RE
    const match = host && /(^|\.)(([\w-]+)\.)?([\w-]+)\.amazonaws\.com(\.cn)?(\:\d+)?$/i.exec(host)
    if (!match) {
        throw new Error(`Hostname '${host}' can't be parsed to extract region/service info`)
    }
    // Extract parts
    let [ serviceName, regionName ] = [ match[4], match[3] ].map(x => x && x.toLowerCase())
    if (regionName) {
        if (isRegion(serviceName)) {
            [ serviceName, regionName ] = [ regionName, serviceName ]
        } else if (!isRegion(regionName)) {
            regionName = DEFAULT_REGION
        }
    } else {
        regionName = DEFAULT_REGION
    }
    // Detect S3 style regions
    if (/^s3-/.test(serviceName) && isRegion(serviceName.substring(3))) {
        [ serviceName, regionName ] = [ 's3', serviceName.substring(3) ]
    }
    // Correct service name
    if (/-fips$/.test(serviceName)) {
        serviceName = serviceName.substring(0, serviceName.length - 5)
    }
    if ({}.hasOwnProperty.call(SERVICE_OVERRIDES, serviceName)) {
        serviceName = SERVICE_OVERRIDES[serviceName]
    }
    return { regionName, serviceName }
}

/**
 * Obtain the (most common) endpoint for a service on a region.
 * This uses the `<service>.<region>` format.
 */
export function formatHost(serviceName: string, regionName?: string, port?: number | string) {
    if ({}.hasOwnProperty.call(ENDPOINT_OVERRIDES, serviceName)) {
        serviceName = ENDPOINT_OVERRIDES[serviceName]
    }
    regionName = regionName ? '.' + regionName : ''
    return `${serviceName}${regionName}.amazonaws.com` + (port ? `:${port}` : '')
}
