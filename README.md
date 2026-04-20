# Overview

## Components
- method (required): The http protocol name the value of it SHALL be `POST`.
- target-uri (required): The URI of the IUA Authorization server.
- authorization (required): The value of the Authorization http header.
- content-digest (required): The digest of the http message as defined in `RFC 9530 Digest Fields`
- created (required): Creation time as a UNIX timestamp value of type Integer.
- expires (required): Expiration time as a UNIX timestamp value of type Integer.
- keyid (optional): The identifier for the key material as a String value.
- tag (optional): An application-specific tag for the signature as a String value which MAY be used to transfer additional information.


# The Signature-Input HTTP Header
The Signature-Input field is a Dictionary Structured Field containing the metadata for the message signatures generated 
from the above components within the HTTP message, e.g.,

```
Signature-Input: sig1=("@method" "@target-uri" "authorization" "content-digest");created=1764073861;created=1764074161;keyid="snIZq-_NvzkKV-IdiM348BCz_RKdwmufnrPubsKKyio";tag="fapi-2-request"
```

# The Signature HTTP Header
The Signature field Shall contain one or more message signatures generated from the signature context of the
target message with a key which uniquely identify the message signature.

# The Content Digest HTTP header
The digest of the http message component serialization as defined in `RFC 9530 Digest Fields`.