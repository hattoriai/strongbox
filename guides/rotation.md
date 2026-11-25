# Rotation

Rotate a key when it may have leaked, when someone who knew it leaves, or
on a schedule. Strongbox does it without downtime.

## 1. A new key, first

```elixir
@impl true
def keys do
  [
    %{tag: "k2", key: Application.fetch_env!(:my_app, :strongbox_key_k2)},
    %{tag: "k1", key: Application.fetch_env!(:my_app, :strongbox_key_k1)}
  ]
end
```

Deploy. New values are written under `"k2"`; values under `"k1"` still
decrypt.

## 2. What is under each key

```elixir
Strongbox.Rotation.report(MyApp.Repo, MyApp.Patient)
#=> %{
#=>   national_id: %{"k2" => 1_204, "k1" => 88_311, nil => 12},
#=>   notes: %{"k2" => 1_150, "k1" => 80_002, nil => 8_375}
#=> }
```

## 3. Writing it again

```elixir
Strongbox.Rotation.run(MyApp.Repo, MyApp.Patient)
#=> {:ok, %{rewritten: 168_313, reindexed: 0, conflicts: 0, unreadable: 0}}
```

`run/3` reads the table in batches, in the order of its primary key, and
writes again each value whose key or format isn't the first key's. It
can run beside your app:

* Each write is a compare-and-swap: a row the app changed after `run/3`
  read it is left alone (a conflict), and the app's own write used the new
  key anyway.
* It writes only what is stale, so it can be stopped and run again.
* `unreadable` counts values none of the keys decrypt. They are left as
  they are: look at them before removing any key.

Run it from a release task, or a job:

```elixir
defmodule MyApp.Release do
  def rotate do
    Application.ensure_all_started(:my_app)
    for schema <- [MyApp.Patient, MyApp.Account], do: Strongbox.Rotation.run(MyApp.Repo, schema)
  end
end
```

## 4. Removing the old key

Once `report/3` shows nothing under `"k1"` in every schema, remove it from
the vault and deploy. Values it encrypted in backups no longer decrypt
with the vault: keep the old key where backups are kept, if you may need
to restore them.

## Index keys

The same steps, with `index_keys/0`. While both keys are there,
`Strongbox.Query.where_index/3` finds rows under either, and `run/3`
hashes each index again under the first. Plain comparisons
(`where: p.email_index == ^email`) see only the first key's hashes, so
use `where_index/3` while a rotation is under way.
