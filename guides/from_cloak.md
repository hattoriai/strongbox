# From Cloak

Strongbox reads what Cloak and Cloak.Ecto wrote, so an app moves over
without a migration of its data: the fields change type, the columns stay
as they are, and the values are written again in Strongbox's format as
they change or as a rotation runs.

## 1. The vault

Give the Cloak keys to a Strongbox vault, after a new Strongbox key. Their
tags are the ones in the Cloak vault's ciphers (`"AES.GCM.V1"` in Cloak's
examples):

```elixir
defmodule MyApp.Vault do
  use Strongbox

  @impl true
  def keys do
    [
      %{tag: "k1", key: Application.fetch_env!(:my_app, :strongbox_key_k1)},
      # Cloak's {Cloak.Ciphers.AES.GCM, tag: "AES.GCM.V1", key: ..., iv_length: 12}
      %{tag: "AES.GCM.V1", key: Application.fetch_env!(:my_app, :cloak_key), format: :cloak, iv_length: 12}
    ]
  end
end
```

`format: :cloak` reads `Cloak.Ciphers.AES.GCM`; give the `iv_length` the
Cloak cipher had, 16 if it had none. `format: :cloak_ctr` reads
`Cloak.Ciphers.AES.CTR`, whose values aren't authenticated (anyone who can
write to the column can change them undetected): rotate those first.

Cloak keys only decrypt, so a Strongbox key comes first.

## 2. The fields

| Cloak.Ecto | Strongbox |
| --- | --- |
| `Cloak.Ecto.Binary` | `encrypted_field :f` |
| `Cloak.Ecto.Integer` | `encrypted_field :f, as: :integer` |
| `Cloak.Ecto.Float` | `encrypted_field :f, as: :float` |
| `Cloak.Ecto.Decimal` | `encrypted_field :f, as: :decimal` |
| `Cloak.Ecto.Date` | `encrypted_field :f, as: :date` |
| `Cloak.Ecto.Time` | `encrypted_field :f, as: :time` |
| `Cloak.Ecto.NaiveDateTime` | `encrypted_field :f, as: :naive_datetime` |
| `Cloak.Ecto.DateTime` | `encrypted_field :f, as: :utc_datetime` |
| `Cloak.Ecto.Map` | `encrypted_field :f, as: :map` |
| `Cloak.Ecto.StringList` | `encrypted_field :f, as: {:array, :string}` |
| `Cloak.Ecto.IntegerList` | `encrypted_field :f, as: {:array, :integer}` |
| `Cloak.Ecto.HMAC` | `blind_index :f_hash, of: :f, compat: :cloak` |

Cloak's values aren't bound to a field. Strongbox reads them all the same,
and binds each value to its field when it writes it again.

## 3. The hashes

`compat: :cloak` keeps the hashes `Cloak.Ecto.HMAC` wrote: give its secret
as the first index key, with its algorithm.

```elixir
@impl true
def index_keys do
  [%{tag: "cloak", key: Application.fetch_env!(:my_app, :cloak_hmac_secret), algorithm: :sha512}]
end
```

To move to Strongbox's own hashes, which key each index apart, add a
second index field without `compat:` and fill it with
`Strongbox.Rotation.run/3`; then look up by it and drop the old one.

## 4. Rotating

```elixir
Strongbox.Rotation.run(MyApp.Repo, MyApp.User)
```

writes every Cloak value again under the Strongbox key, bound to its
field. Once `Strongbox.Rotation.report/3` shows no Cloak tag left, remove
the Cloak keys, then Cloak.

## From Ecto.Encrypted

`Ecto.Encrypted` writes what Strongbox calls the `:ecto` format, and any
Strongbox key reads it with the same tag and key. Give the vault the keys
of your `Ecto.Encrypted` module, a new key first, and rotate. To keep
writing in `Ecto.Encrypted`'s format, so that it can still read
everything, give the first key `format: :ecto`; its values are then not
bound to their field.
