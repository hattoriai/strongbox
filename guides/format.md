# Format

Strongbox's values and hashes can be read without Strongbox: this is every
byte of them. It is the contract of the library, and changes only with a
new version byte.

## Encrypted values

### Version 2: Strongbox

```
<<2, flags, tag_size, tag::binary-size(tag_size),
  salt::binary-12, commitment::binary-16, iv, ciphertext, auth_tag::binary-16>>
```

* `flags`: bit 0 is set when the plaintext is padded.
* `tag`: the key's tag, 1 to 127 bytes.
* `salt`: 12 random bytes.
* `iv`: the cipher's IV length of random bytes, 12 for each cipher
  Strongbox takes.
* `auth_tag`: the AEAD tag, 16 bytes.

From the key and the salt, with HMAC-SHA256:

```
prk        = HMAC(key, "Strongbox v2" || salt)
value_key  = HMAC(prk, "key" || 0x01), its first key_length bytes
commitment = HMAC(prk, "commitment" || 0x01), its first 16 bytes
```

The value is encrypted with the key's AEAD cipher, under `value_key`, with
the additional data

```
<<2, flags, tag_size, tag>> || context
```

where `context` is the field's context (its name, by default), or empty.
Decrypting compares the commitment first, in constant time: a value can't
be made to decrypt under two keys.

When padded, the plaintext is followed by `0x80`, then zeros up to a
multiple of the block; decrypting removes everything from the last `0x80`.

### Version 1: Ecto.Encrypted

```
<<1, tag_size, tag, salt::binary-12, iv, ciphertext, auth_tag::binary-16>>
```

with `value_key` the first `key_length` bytes of `HMAC-SHA256(key,
"Ecto.Encrypted" || salt)` and the additional data `<<1, tag_size, tag>>`.
No context, no padding. Strongbox writes it for keys with `format: :ecto`,
and reads it with any key.

### Cloak (read only)

`Cloak.Ciphers.AES.GCM`, for tags shorter than 128 bytes:

```
<<1, tag_size, tag, iv::binary-size(iv_length), auth_tag::binary-16, ciphertext>>
```

AES-256-GCM under the key itself, with the additional data `"AES256GCM"`.
`Cloak.Ciphers.AES.CTR`: `<<1, tag_size, tag, iv::binary-16, ciphertext>>`,
AES-256-CTR, not authenticated.

Versions 1 and Cloak share their first byte; the key with the value's tag
says which it is.

## What is encrypted

What `:as` holds becomes a binary before it is encrypted, as Cloak.Ecto
does:

| `:as` | binary |
| --- | --- |
| `:binary`, `:string` | as it is |
| `:integer`, `:float`, `:decimal` | its text: `"42"`, `"1.5"` |
| `:boolean` | `"true"`, `"false"` |
| `:date`, `:time`, `:naive_datetime`, `:utc_datetime` | ISO 8601 |
| `:map`, `{:array, _}` | JSON |

With `encoding: :base64`, the stored value is the Base64 of the bytes
above.

## Blind indexes

```
index_key = HMAC(algorithm, key, "Strongbox.Index " || context)
hash      = HMAC(algorithm, index_key, value)
          or PBKDF2-HMAC(algorithm, value, salt = index_key, iterations, hash size)
```

`value` is the binary above, normalized; `context` is the index's (its
name, by default). With `:bytes`, the hash's first bytes.

With `compat: :ecto`, `HMAC(algorithm, key, "Ecto.HMAC" || value)`, as
`Ecto.HMAC`. With `compat: :cloak`, `HMAC(algorithm, key, value)`, as
`Cloak.Ecto.HMAC`.
