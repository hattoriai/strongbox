# Keys

A vault has two lists of keys: `keys/0` encrypt and decrypt, `index_keys/0`
hash blind indexes. They are never the same keys.

## Making a key

```sh
$ mix strongbox.gen.key
```

prints 32 random bytes in Base64: a key for AES-256-GCM, ChaCha20-Poly1305
or an index under SHA-256. `--bytes 16` makes one for AES-128-GCM,
`--bytes 64` one for an index under SHA-512.

## Keeping a key

Keep keys in environment variables, or in your platform's secrets, never
in the code or the repository. Decode them once, in `config/runtime.exs`:

```elixir
if config_env() == :prod do
  config :my_app,
    strongbox_key_k1: Strongbox.Key.decode!(System.fetch_env!("STRONGBOX_KEY_K1")),
    strongbox_index_key_i1: Strongbox.Key.decode!(System.fetch_env!("STRONGBOX_INDEX_KEY_I1"))
end
```

and read them in the vault:

```elixir
@impl true
def keys do
  [%{tag: "k1", key: Application.fetch_env!(:my_app, :strongbox_key_k1)}]
end
```

The vault's functions are called for every value, so they must be
cheap: never decode or fetch keys in them.

* Never put a key in a module attribute: it would be written into the
  compiled `.beam` file.
* Never derive keys from `secret_key_base` or another secret that may
  change for reasons of its own: the data would no longer decrypt.
* Use other keys in development and tests than in production.

Strongbox never shows a key: `inspect/1` of a `Strongbox.Key` gives its
tag, errors name the tag, and errors inside `:crypto` lose their
arguments before they reach a report.

## Tags

A key's tag is written in front of each value it encrypts, so Strongbox
knows which key decrypts it. Tags are short and never reused for another
key: `"k1"`, `"k2"`, or a date, `"2026-11"`.

Keys that come without a name, such as a list in one environment
variable, get their tags from `Strongbox.Key.tag/1`: the first 4 bytes of
the key's SHA-256, in hex. A key always has the same tag, so the list can
change without a name for each key:

```elixir
# config/runtime.exs
keys =
  for encoded <- String.split(System.fetch_env!("STRONGBOX_KEYS"), ","),
      key = Strongbox.Key.decode!(encoded) do
    %{tag: Strongbox.Key.tag(key), key: key}
  end

config :my_app, strongbox_keys: keys
```

## Ciphers

`:aes_256_gcm` by default. `:chacha20_poly1305` is as strong and faster on
machines without AES instructions; `:aes_128_gcm` and `:aes_256_ccm` are
there too. Each key has its own cipher, so changing cipher is rotating to
a key with another one:

```elixir
[
  %{tag: "k2", key: k2, cipher: :chacha20_poly1305},
  %{tag: "k1", key: k1}
]
```

## How many keys

One for every field is usual: each value is encrypted under a key of its
own, derived from the vault's key and a random salt, and bound to its
field. Use several vaults when some data must be readable by a part of
the system that mustn't read the rest.
