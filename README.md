# a4s

This is a set of functions that implement the AWS v4 signature process.
In addition to implementing the general HTTP case, generic internals
and service-specific implementations are provided (i.e. S3, Cloudfront, etc.).

## Modules

 - [**`core`: Generic message signing**](https://a4s.alba.sh/docs/modules/_core_.html)

 - [**`http`: HTTP signing**](https://a4s.alba.sh/docs/modules/_http_.html)
   - `Authorization` request signing
   - Query signing (presigned URLs)

 - [**`s3`: S3 service specific**](https://a4s.alba.sh/docs/modules/_s3_.html)
   - `Authorization` request signing
     - Unsigned payload
     - [**`s3.chunked`: Chunked Upload (streaming payload)**](https://a4s.alba.sh/docs/modules/_s3_chunked_.html)
   - Query signing (presigned URLs)
   - POST form authorization (signed policy)

#### A note about headers

This library assumes there are no illegal characters in header names (i.e.
whitespace) or values (i.e. control chars). If there are, Node.JS will fail
when making the request.

Duplicate headers with different capitalizations (such as `{ 'Header':
'value1', 'HEADER': 'value2' }`) will be rejected with an error, because
it causes undefined behaviour when sending the request.

AWS doesn't define how non-ASCII characters are handled in header values,
so the generated signature may not work in those cases.
