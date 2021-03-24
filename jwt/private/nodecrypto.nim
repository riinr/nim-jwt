import jose


proc signString*(algorithm: Algorithm, toSign: string, secret: string): seq[byte] =
    @[]


proc verifySignature*(algorithm: Algorithm, data: string, signature: seq[byte], secret: string): bool =
    false
    