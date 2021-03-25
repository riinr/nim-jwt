import json, strutils

from base64 import nil


type
  KeyError = object of ValueError

proc checkJsonNodeKind*(node: JsonNode, kind: JsonNodeKind) =
  # Check that a given JsonNode has a given kind, raise InvalidClaim if not
  if node.kind != kind:
    raise newException(ValueError, "Invalid kind")


proc checkKeysExists*(node: JsonNode, keys: varargs[string]) =
  for key in keys:
    if not node.hasKey(key):
      raise newException(KeyError, "$# is not present." % key)

proc makeItSafe*(s: string): string =
  result = s
  while result.endsWith("="):
    result.setLen(result.len - 1)
  result = result.replace('+', '-').replace('/', '_')

proc encodeUrlSafe*(s: openarray[byte]): string =
  when NimMajor >= 1 and (NimMinor >= 1 or NimPatch >= 2):
    makeItSafe(base64.encode(s))
  else:
    makeItSafe(base64.encode(s, newLine=""))

proc encodeUrlSafe*(s: openarray[char]): string {.inline.} =
  encodeUrlSafe(s.toOpenArrayByte(s.low, s.high))

proc decodeUrlSafeAsString*(s: string): string =
  var s = s.replace('-', '+').replace('_', '/')
  while s.len mod 4 > 0:
    s &= "="
  base64.decode(s)

proc decodeUrlSafe*(s: string): seq[byte] =
  cast[seq[byte]](decodeUrlSafeAsString(s))

