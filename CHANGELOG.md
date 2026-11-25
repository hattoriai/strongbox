# Changelog

All notable changes to Strongbox are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Strongbox follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Vaults (`use Strongbox`): keys from a callback, no process. AES-GCM,
  AES-CCM and ChaCha20-Poly1305 from `:crypto`, a key per value from a
  random salt, and a commitment to the key checked before decrypting.
- `Strongbox.Encrypted`, an encrypted field: binaries, strings, numbers,
  decimals, booleans, dates and times, maps and lists. Each value bound to
  its field's name (`:context`), optional padding (`:pad`), Base64 for text
  columns and embeds (`encoding: :base64`).
- `Strongbox.Index`, a blind index: normalizers, a key per index, short
  hashes (`:bytes`), slow hashes (`:iterations`), and `Ecto.HMAC`'s and
  `Cloak.Ecto.HMAC`'s hashes (`:compat`).
- `Strongbox.Schema`: `encrypted_field/2` and `blind_index/2`, always
  redacted.
- `Strongbox.Changeset.put_indexes/2` and `Strongbox.Query.where_index/3`,
  which looks up under every index key.
- `Strongbox.Rotation`: `report/3`, and `run/3`, which writes again what
  isn't under the first key, by compare-and-swap.
- Reading `Ecto.Encrypted`'s format, and writing it (`format: :ecto`);
  reading Cloak's AES.GCM and AES.CTR (`format: :cloak`, `:cloak_ctr`).
- `mix strongbox.gen.key`.

### Fixed

- `Strongbox.Rotation.run/3` on SQLite: it wrote nothing, and counted
  every value as a conflict. It compared the stored bytes with a
  parameter SQLite took for a text, which is never equal to a BLOB.
