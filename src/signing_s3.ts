/**
 * This module contains signing logic that is specific for the S3 service.
 *
 *  - For `Authorization`-based signing, the process is the same as for any
 *    other HTTP request but path normalization & double encoding must be disabled.
 *    In addition to the usual `Host` and `x-amz-date` requirements, S3
 *    requests also need to contain an `x-amz-content-sha256` and
 *    `x-amz-expires` parameter somewhere.  
 *    **See {{signRequestHeader}} and {{autoSignRequestHeader}}**.
 *
 *  - For query-based signing the process is almost identical to the above
 *    except that instead of an `Authorization` header, query parameters
 *    are added to sign the request.  
 *    **See {{signRequestQuery}} and {{autoSignRequestQuery}}.**
 *
 *  - Additionally there's POST form parameter authentication,
 *    which is designed mainly to allow users to upload files
 *    to S3 directly from their browser.  
 *    **See {{signPolicy}}.**
 */

import { getCanonical } from './signing_http'
import { formatTimestamp, getSigningData, signString,
    MAIN_ALGORITHM, RelaxedCredentials, Credentials, GetSigningData } from './signing'
import { DEFAULT_REGION } from './endpoint_utils'

export interface PolicySignOptions {
    timestamp?: string | Date
    getSigningData?: GetSigningData
}

export const UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD'
export const STREAMING_PAYLOAD = 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'

export function signRequestHeader() {

}

export function signRequestQuery() {

}

/**
 * (POST form param based authentication)
 *
 * This method signs the passed policy and returns the
 * [authentication parameters][policy-auth] that you need to attach
 * to the [created form][create-form].
 *
 * See [this][construct-policy] for how to write the policy.
 * The policy shouldn't contain any authentication parameters (such
 * as `x-amz-date`); these will be added before signing it.
 *
 * @param credentials The IAM credentials to use for signing
 *                   (service name defaults to 's3', and the default region)
 * @param policy The policy object
 * @param timestamp You can optionally provide the timestamp for signing,
 *                  otherwise it will be generated using {{formatTimestamp}}
 * @returns Key - value object containing the form parameters
 *
 * [create-form]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTForms.html
 * [construct-policy]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
 * [policy-auth]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-authentication-HTTPPOST.html
 */
export function signPolicy(
    credentials: RelaxedCredentials,
    policy: any,
    options?: PolicySignOptions
): {[key: string]: string} {
    const { accessKey, secretKey, regionName, serviceName } = credentials
    const derive = (options && options.getSigningData) || getSigningData
    const ts = options && options.timestamp

    // Get timestamp, derive key, prepare form fields
    const timestamp = (typeof ts === 'string') ? ts : formatTimestamp(ts)
    const { key, scope } = derive(timestamp, secretKey,
        regionName || DEFAULT_REGION, serviceName || 's3')
    const fields: {[key: string]: string} = {
        'x-amz-date': timestamp,
        'x-amz-algorithm': MAIN_ALGORITHM,
        'x-amz-credential': `${accessKey}/${scope}`,
    }

    // Add the fields to the policy conditions
    const conditions = (policy.conditions || []).concat(
        Object.keys(fields).map(k => ({ [k]: fields[k] })))
    const finalPolicy = JSON.stringify({ ...policy, conditions })

    // Encode and sign the policy
    const encodedPolicy = Buffer.from(finalPolicy).toString('base64')
    const signature = signString(key, encodedPolicy).toString('hex')

    return { ...fields, 'policy': encodedPolicy, 'x-amz-signature': signature }
}
