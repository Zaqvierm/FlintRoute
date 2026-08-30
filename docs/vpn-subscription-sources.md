# VPN subscription source resolution

This document describes the source boundary used by the VLESS subscription
pipeline. A value entered in the UI is an **original source**, not necessarily
an HTTP URL.

## Pipeline

```text
original source
  -> normalization
  -> syntax and crypto-version detection
  -> version-specific decoder
  -> canonical HTTPS URL
  -> SSRF-protected fetch
  -> provider response parsing
  -> typed VLESS pool and candidate bundle
```

`OriginalSource` remains the source of truth and is retained in the protected
subscription file. `ResolvedSource` exists only in memory for the fetch and
provider identity calculation. API responses and pool snapshots contain only
masked forms (`original_source_masked` and `resolved_source_masked`). Full
subscription URLs, payloads, UUIDs and HWIDs are not written to logs or events.

## Accepted source forms

The normalizer accepts plain `https://` URLs and Happ forms such as
`happ://crypt4/<payload>`, including escaped separators (`happ\\://` and
`happ:\\/\\/`) and an URL-encoded separator. It intentionally does not
URL-decode the complete URI: `%2B`, `%2F` and `%3D` in the ciphertext are
payload data and are decoded only by the selected decoder.

Plain HTTP is rejected. A recognized but unavailable crypto version is
reported as `decoder_unavailable`, not as a generic malformed subscription.
The prefix is authoritative: a `crypt5` value is never passed to the crypt4
decoder.

## crypt4

`internal/vpnsub/source.go` implements the proven crypt4 contract:

1. remove the `happ://crypt4/` prefix and URL-decode the payload;
2. accept standard or URL-safe Base64 with optional padding;
3. require a non-empty ciphertext whose length is a multiple of 512 bytes;
4. decrypt each 512-byte block independently with the provisioned RSA-4096
   PKCS#1 v1.5 private key and concatenate blocks in order;
5. require valid UTF-8 containing a valid HTTP(S) subscription URL.

The known protocol key is kept in the dedicated crypt4 adapter. A deployment
may override it through `FLINTROUTE_HAPP_CRYPT4_KEY_FILE` or the fixed
protected path `/etc/router-policy/secrets/happ-crypt4-private-key.pem`.
An invalid explicit override is an explicit `decoder_unavailable` state;
FlintRoute does not guess a key.

The block-by-block RSA and Happ version separation match the public reference
contract inspected during implementation ([hpwnr source](https://github.com/Omegaplexx/hpwnr)); no upstream code is imported.

## crypt5 and future versions

`crypt`, `crypt2`, `crypt3`, `crypt5` and future numeric `cryptN` prefixes are
recognized by syntax and currently return `decoder_unavailable` unless an
exact-version decoder is registered. They are not attempted with the crypt4
RSA decoder. A future implementation adds a `SourceDecoder` for that exact
version without changing fetch, parsing or transaction code.

## Provider HWID

Happ requests may include `X-HWID`. The header is provider-specific and is not
added to ordinary FlintRoute HTTP requests. Settings are stored beside the
protected subscription file in a separate mode-0600 file.

Generated HWIDs use a fixed, ordered, normalized fingerprint and HMAC-SHA256
namespace `flintroute-hwid-v1`; the first 16 bytes are formatted as an RFC 4122
UUID (version/variant bits are set deterministically). Restarting the router
with unchanged selected components therefore produces the same identifier.
Preset mode uses a validated UUID verbatim; disabled mode sends no HWID.

## Refresh and failure semantics

Every refresh starts from `OriginalSource`, resolves it again, derives/loads the
current HWID and fetches into a temporary file. Only a validated candidate can
enter the existing FlintRoute ChangeSet/transaction flow. Decoder failure,
provider 401/403, malformed content, empty content or SSRF rejection leaves the
last active bundle untouched and reports a typed diagnostic (`hwid_rejected`,
`upstream_http_failure`, `base64_decode_failure`, `decrypt_failure`, and so
on).

The UI exposes one source row initially and adds rows explicitly. It displays
source type, crypto version and masked resolution status. VLESS server views
are shown only while Xray is available; latency, health and throughput remain
separate metrics.
