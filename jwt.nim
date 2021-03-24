import json, strutils, tables, times

import jwt/private/[claims, crypto, jose, utils]

type
  InvalidToken* = object of ValueError

  JWT* = object
    headerB64: string
    claimsB64: string
    header*: JOSEHeader
    claims*: TableRef[string, Claim]
    signature*: seq[byte]

export claims
export jose

proc splitToken(s: string): seq[string] =
  let parts = s.split(".")
  if parts.len != 3:
    raise newException(InvalidToken, "Invalid token")
  result = parts

proc initJWT*(header: JOSEHeader, claims: TableRef[string, Claim], signature: seq[byte] = @[]): JWT =
  JWT(
    headerB64: header.toBase64,
    claimsB64: claims.toBase64,
    header: header,
    claims: claims,
    signature: signature
  )

# Load up a b64url string to JWT
proc toJWT*(s: string): JWT =
  var parts = splitToken(s)
  let
    headerB64 = parts[0]
    claimsB64 = parts[1]
    headerJson = parseJson(decodeUrlSafeAsString(headerB64))
    claimsJson = parseJson(decodeUrlSafeAsString(claimsB64))
    signature = decodeUrlSafe(parts[2])

  JWT(
    headerB64: headerB64,
    claimsB64: claimsB64,
    header: headerJson.toHeader(),
    claims: claimsJson.toClaims(),
    signature: signature
  )

proc toJWT*(node: JsonNode): JWT =
  initJWT(node["header"].toHeader, node["claims"].toClaims)

# Encodes the raw signature to b64url
proc signatureToB64(token: JWT): string =
  assert token.signature.len != 0
  result = encodeUrlSafe(token.signature)

proc loaded*(token: JWT): string =
  token.headerB64 & "." & token.claimsB64

proc parsed*(token: JWT): string =
  result = token.header.toBase64 & "." & token.claims.toBase64

proc sign*(token: var JWT, secret: string) =
  assert token.signature.len == 0
  let alg = token.header.alg
  token.signature = alg.signString(token.parsed, secret)

# Verify a token typically an incoming request
proc verify*(token: JWT, secret: string, alg: Algorithm): bool =
  token.header.alg == alg and alg.verifySignature(token.loaded, token.signature, secret)

proc toString*(token: JWT): string =
  token.header.toBase64 & "." & token.claims.toBase64 & "." & token.signatureToB64


proc `$`*(token: JWT): string =
  token.toString


proc `%`*(token: JWT): JsonNode =
  let s = $token
  %s

proc verifyTimeClaims*(token: JWT) =
  let now = getTime()
  if token.claims.hasKey("nbf"):
    let nbf = token.claims["nbf"].getClaimTime
    if now < nbf:
      raise newException(InvalidToken, "Token cant be used yet")

  if token.claims.hasKey("exp"):
    let exp = token.claims["exp"].getClaimTime
    if now > exp :
      raise newException(InvalidToken, "Token is expired")

  # Verify token nbf exp
