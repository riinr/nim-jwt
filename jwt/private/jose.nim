import json, strutils

import utils

type
  CryptoException* = object of ValueError
  UnsupportedAlgorithm* = object of CryptoException

  AlgorithmSize* {. pure .} = enum
    S256 = 256
    S384 = 384
    S512 = 512

  AlgorithmKind* {. pure .} = enum
    HS
    RS
    ES
  
  Algorithm* = object
    kind*: AlgorithmKind
    size*: AlgorithmSize

  JOSEHeader* = object
    alg*: Algorithm
    typ*: string


proc createAlgorithm*(kind: AlgorithmKind, size: AlgorithmSize): Algorithm =
  result.kind = kind
  result.size = size


let
  HS256* = createAlgorithm(HS, S256)
  HS384* = createAlgorithm(HS, S384)
  HS512* = createAlgorithm(HS, S512)
  RS256* = createAlgorithm(RS, S256)
  RS384* = createAlgorithm(RS, S384)
  RS512* = createAlgorithm(RS, S512)
  ES256* = createAlgorithm(ES, S256)
  ES384* = createAlgorithm(ES, S384)
  ES512* = createAlgorithm(ES, S512)


proc `$`*(algorithm: Algorithm): string =
  $algorithm.kind & $algorithm.size.ord


proc strToAlgorithmKind(s: string): AlgorithmKind =
  if s.startsWith("HS"):
    return HS
  elif s.startsWith("RS"):
    return RS
  elif s.startsWith("ES"):
    return ES
  else:
    raise newException(UnsupportedAlgorithm, "$# isn't supported" % s)


proc strToAlgorithmSize(s: string): AlgorithmSize =
  if s.endsWith("256"):
    return S256
  elif s.endsWith("384"):
    return S384
  elif s.endsWith("512"):
    return S512
  else:
    raise newException(UnsupportedAlgorithm, "$# isn't supported" % s)  


proc strToAlgorithm(s: string): Algorithm =
  result.kind = s.strToAlgorithmKind
  result.size = s.strToAlgorithmSize


proc toHeader*(node: JsonNode): JOSEHeader =
  # Check that the keys are present so we dont blow up.
  node.checkKeysExists("alg", "typ")

  let algStr = node["alg"].getStr()
  let algo = strToAlgorithm(algStr)

  result = JOSEHeader(
    alg: algo,
    typ: node["typ"].getStr()
  )


proc `%`*(alg: Algorithm): JsonNode =
  let s = $alg
  return %s


proc `%`*(h: JOSEHeader): JsonNode =
  return %{
    "alg": %h.alg,
    "typ": %h.typ
  }


proc toBase64*(h: JOSEHeader): string =
  let asJson = %h
  result = encodeUrlSafe($asJson)
