# a4s

This is a set of functions that implement the AWS v4 signature process.
In addition to implementing the general HTTP case, generic internals
and service-specific implementations are provided (i.e. S3, Cloudfront, etc.).

#### A note about headers

This library assumes there are no illegal characters in header names (i.e.
whitespace) or values (i.e. control chars). If there are, Node.JS will fail
when making the request.

Duplicate headers with different capitalizations (such as `{ 'Header':
'value1', 'HEADER': 'value2' }`) will be rejected with an error, because
it causes undefined behaviour when sending the request.

AWS doesn't define how non-ASCII characters are handled in header values,
so the generated signature may not work in those cases.
