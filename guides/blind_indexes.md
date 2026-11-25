# Blind indexes

Each encrypted value has a random salt, so `where: p.email == ^email`
matches nothing. A blind index is a keyed hash of the value, kept in a
column beside it. The same value always has the same hash, so it can be
looked up, and have a unique index.

```elixir
encrypted_field :email, as: :string
blind_index :email_index, of: :email, normalize: [:trim, :downcase]
```

```elixir
# the migration
add :email, :binary
add :email_index, :binary
create unique_index(:patients, [:email_index])
```

The vault needs index keys, never the same as its encryption keys:

```elixir
@impl true
def index_keys do
  [%{tag: "i1", key: Application.fetch_env!(:my_app, :strongbox_index_key_i1)}]
end
```

## Keeping it in step

`Strongbox.Changeset.put_indexes/1` copies each changed field into the
indexes whose `:of` names it:

```elixir
def changeset(patient, attrs) do
  patient
  |> cast(attrs, [:email])
  |> Strongbox.Changeset.put_indexes()
  |> unique_constraint(:email_index)
end
```

## Looking up

```elixir
Patient |> Strongbox.Query.where_index(:email_index, "Ana@Example.com") |> Repo.one()
```

asks for the value's hash under each index key, so lookups keep working
while index keys rotate. A plain comparison, `where: p.email_index ==
^"ana@example.com"`, works too, under the first index key only.

## Normalizing

Lookups ignore what `:normalize` takes away, applied in order:

* `:trim`, and `:squish` (runs of whitespace as one space)
* `:downcase`, `:upcase`
* `:nfc`, `:nfkc` (Unicode: `"é"` typed two ways is one value)
* `:digits`, only the digits: `"+351 912 345 678"` is `"351912345678"`
* `{module, function}`, your own

The encrypted field keeps the value as given.

## Each index its own key

The hash is keyed with a key derived from the index key and the index's
name, so the same email has unrelated hashes in `email_index` and in
`backup_email_index`: two indexes can't be joined to tell they hold the
same person. Give `context:` to keep the hashes when you rename the
field.

## What an index gives away

A hash hides the value, not which rows share it, nor how often each value
appears. Someone with the table sees that two patients have the same
email, and which value is the most common. With the index key too, a
value with few possibilities can be guessed by hashing them all.

So index only what you look up, and choose:

* **Short hashes.** `bytes: 4` keeps 4 bytes of each hash. Unrelated
  values then share hashes now and then, so a lookup returns a few rows
  and you keep the one whose decrypted value matches, and the index tells
  less about which rows are equal. Not for unique indexes.

  ```elixir
  blind_index :last_name_index, of: :last_name, normalize: [:downcase], bytes: 3
  ```

* **Slow hashes.** `iterations: 10_000` hashes with PBKDF2, so guessing
  phone numbers or dates of birth takes thousands of times longer, even
  with the index key. Each write and each lookup pays for it too: a few
  milliseconds.

  ```elixir
  blind_index :phone_index, of: :phone, normalize: [:digits], iterations: 10_000
  ```

## Rotating index keys

Put the new index key first and deploy: new hashes use it, and
`where_index/3` finds rows under either key. `Strongbox.Rotation.run/3`
then hashes each index again under the new key. Then remove the old one.
See [Rotation](rotation.md).
