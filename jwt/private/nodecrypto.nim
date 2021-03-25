import jsffi, base64
import jose, utils

let crypto = require("crypto")


proc hmac(algorithm: Algorithm, toSign, secret: string): seq[byte] =
    let hash = crypto.createHmac("sha" & $algorithm.size.ord, secret)
        .update(toSign)
        .digest("base64")
    decodeUrlSafe(makeItSafe($hash.to(cstring)))


proc signRSPem(algorithm: Algorithm, toSign, secret: string): seq[byte] =
    let
        privateKey = crypto.createPrivateKey(secret)
        hash = crypto.createSign("RSA-SHA" & $algorithm.size.ord)
            .update(toSign)
            .sign(privateKey, "base64")

    decodeUrlSafe(makeItSafe($hash.to(cstring)))


proc verifyRSPem(algorithm: Algorithm, data, secret: string, signature: seq[byte]): bool =
    let 
        publicKey = crypto.createPublicKey(secret)
        verifier = crypto.createVerify("RSA-SHA" & $algorithm.size.ord)
            .update(data)
            .end()
    verifier.verify(publicKey, encode(signature), "base64").to(bool)


proc signString*(algorithm: Algorithm, toSign: string, secret: string): seq[byte] =
    case algorithm.kind
    of HS:
        algorithm.hmac(toSign, secret)
    of RS:
        algorithm.signRSPem(toSign, secret)
    of ES:
        raise newException(LibraryError, "Unimplemented " & $algorithm)


proc verifySignature*(algorithm: Algorithm, data: string, signature: seq[byte], secret: string): bool =
    case algorithm.kind
    of HS:
        algorithm.signString(data, secret) == signature
    of RS:
        algorithm.verifyRSPem(data, secret, signature)
    of ES:
        raise newException(LibraryError, "Unimplemented " & $algorithm)
    