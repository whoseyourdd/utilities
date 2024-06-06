# utilities
The "Utilities" module is an open-source project developed in Golang. This module houses a comprehensive set of tools designed to assist in various tasks. A noteworthy feature of this module is a utility for JWT (JSON Web Token).

For those looking to utilize or contribute to the Utilities module, it can be accessed through the following GitHub repository: `go get github.com/whoseyourdd/utilities`.

Currently, the Utilities module includes a JWT generator, which can be accessed via the function `netutils.GenerateJWTToken()`. This function requires a JWTPayload and a secret key for operation. For decrypting the token, the `netutils.GetDecryptedPayload()` function is available, which requires the JWT token (*string) and the secret key used for encryption.

We highly encourage contributions, suggestions, and ideas from the community. Your input can help enhance this module, making it a more valuable resource for all Golang developers.
