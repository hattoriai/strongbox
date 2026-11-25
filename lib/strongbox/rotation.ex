defmodule Strongbox.Rotation do
  @moduledoc """
  Rotating keys: what is still under the old ones, and writing it again
  under the new.

  Put the new key first in the vault's `c:Strongbox.keys/0`, keep the old
  ones after it, and deploy. New values are written under the new key and
  the old ones still decrypt. Then:

      Strongbox.Rotation.report(MyApp.Repo, MyApp.User)
      #=> %{email: %{"k2" => 1_204, "k1" => 88_311, nil => 12}, ...}

      Strongbox.Rotation.run(MyApp.Repo, MyApp.User)
      #=> {:ok, %{rewritten: 88_311, reindexed: 0, conflicts: 0, unreadable: 0}}

  Once `report/3` shows nothing under a key, remove it from the vault.

  `run/3` goes through the table in batches, in the order of its primary
  key, and writes again each value whose key or format isn't the first
  key's. It can be stopped and run again: it only writes what is stale.
  Each write is a compare-and-swap: a row changed since it was read isn't
  written (it counts as a conflict, and the change already used the new
  key), so `run/3` is safe beside the app's own writes. Run it from a
  release task or a background job.

  Blind indexes are hashed again when the first index key changes:
  `run/3` reads each indexed field, and writes its index if its hash under
  the first index key isn't the one stored. Lookups with
  `Strongbox.Query.where_index/3` find rows under any index key meanwhile.

  It needs a schema with a single primary key.
  """

  import Ecto.Query

  alias Strongbox.{Changeset, Cipher, Encrypted, Index}

  @type summary :: %{
          rewritten: non_neg_integer,
          reindexed: non_neg_integer,
          conflicts: non_neg_integer,
          unreadable: non_neg_integer
        }

  @doc """
  Counts the values of each encrypted field of `schema` by the tag of the
  key they were written with. `nil` counts the rows where the field is
  `nil`; `:unreadable`, values that aren't in any known format.

  Options: `:fields`, the encrypted fields to count (all by default);
  `:batch_size`, 1000 by default.
  """
  @spec report(Ecto.Repo.t(), module, keyword) :: %{
          atom => %{(binary | nil | :unreadable) => non_neg_integer}
        }
  def report(repo, schema, opts \\ []) do
    for field <- encrypted_fields(schema, opts), into: %{} do
      params = encrypted_params!(schema, field)

      counts =
        schema
        |> raw_rows(repo, [field], opts)
        |> Enum.reduce(%{}, fn {_id, [raw]}, counts ->
          Map.update(counts, tag(raw, params), 1, &(&1 + 1))
        end)

      {field, counts}
    end
  end

  @doc """
  Writes again the values of `schema` that aren't under the first key, and
  hashes again the blind indexes that aren't under the first index key.

  Returns `{:ok, summary}`: how many values were `rewritten`, how many
  indexes `reindexed`, how many rows changed meanwhile (`conflicts`, left
  as they are), and how many values none of the keys decrypt
  (`unreadable`, left as they are).

  Options:

    * `:fields` - the encrypted fields to rotate, all by default.
    * `:indexes` - whether to hash blind indexes again, `true` by default.
    * `:batch_size` - rows read at a time, 500 by default.
  """
  @spec run(Ecto.Repo.t(), module, keyword) :: {:ok, summary}
  def run(repo, schema, opts \\ []) do
    summary = %{rewritten: 0, reindexed: 0, conflicts: 0, unreadable: 0}

    summary =
      Enum.reduce(encrypted_fields(schema, opts), summary, fn field, summary ->
        rotate_field(repo, schema, field, opts, summary)
      end)

    summary =
      if Keyword.get(opts, :indexes, true) do
        schema
        |> Changeset.indexes()
        |> Enum.reduce(summary, fn {index, of}, summary ->
          reindex(repo, schema, index, of, opts, summary)
        end)
      else
        summary
      end

    {:ok, summary}
  end

  defp rotate_field(repo, schema, field, opts, summary) do
    params = encrypted_params!(schema, field)

    schema
    |> raw_rows(repo, [field], Keyword.put_new(opts, :batch_size, 500))
    |> Enum.reduce(summary, fn
      {_id, [nil]}, summary -> summary
      {id, [raw]}, summary -> rotate_value(repo, schema, field, params, id, raw, summary)
    end)
  end

  defp rotate_value(repo, schema, field, params, id, raw, summary) do
    with {:ok, ciphertext} <- Encrypted.ciphertext(raw, params),
         true <- Strongbox.stale?(params.vault, ciphertext),
         {:ok, value} <- Encrypted.load(raw, nil, params) do
      count(summary, swap(repo, schema, id, [{field, raw}], [{field, value}]), :rewritten)
    else
      false -> summary
      :error -> bump(summary, :unreadable)
    end
  end

  defp reindex(repo, schema, index, of, opts, summary) do
    index_params = Index.params!(schema, index)
    of_params = encrypted_params!(schema, of)

    schema
    |> raw_rows(repo, [of, index], Keyword.put_new(opts, :batch_size, 500))
    |> Enum.reduce(summary, fn {id, [of_raw, index_raw]}, summary ->
      reindex_row(
        repo,
        schema,
        {index, index_params, index_raw},
        {of, of_params, of_raw},
        id,
        summary
      )
    end)
  end

  defp reindex_row(_repo, _schema, {_index, _params, nil}, {_of, _of_params, nil}, _id, summary),
    do: summary

  defp reindex_row(repo, schema, {index, _params, index_raw}, {of, _of_params, nil}, id, summary) do
    swap(repo, schema, id, [{of, nil}, {index, index_raw}], [{index, nil}])
    |> then(&count(summary, &1, :reindexed))
  end

  defp reindex_row(repo, schema, {index, params, index_raw}, {of, of_params, of_raw}, id, summary) do
    with {:ok, value} <- Encrypted.load(of_raw, nil, of_params),
         {:ok, hash} when hash != index_raw <- Index.dump(value, nil, params) do
      swap(repo, schema, id, [{of, of_raw}, {index, index_raw}], [{index, value}])
      |> then(&count(summary, &1, :reindexed))
    else
      {:ok, _same} -> summary
      :error -> bump(summary, :unreadable)
    end
  end

  # Sets `changes` (values the fields' types dump: encrypt, hash) where the
  # row still holds `expected` (stored values, compared as stored: as the
  # column's own type, a binary or a text, and not as the field's, which
  # would encrypt or hash them again. Without a type, SQLite takes a
  # binary for a text, which is never equal to the column's BLOB).
  defp swap(repo, schema, id, expected, changes) do
    [pk] = schema.__schema__(:primary_key)

    query =
      Enum.reduce(expected, from(r in schema, where: field(r, ^pk) == ^id), fn
        {field, nil}, query ->
          where(query, [r], is_nil(field(r, ^field)))

        {field, raw}, query ->
          stored = Ecto.Type.type(schema.__schema__(:type, field))
          where(query, [r], fragment("? = ?", field(r, ^field), type(^raw, ^stored)))
      end)

    case repo.update_all(query, set: changes) do
      {1, _} -> :ok
      {0, _} -> :conflict
    end
  end

  defp count(summary, :ok, key), do: bump(summary, key)
  defp count(summary, :conflict, _key), do: bump(summary, :conflicts)

  defp bump(summary, key), do: Map.update!(summary, key, &(&1 + 1))

  # Streams {primary key, [stored value of each field]}, in batches, in the
  # order of the primary key. The values are read as stored (fragments are
  # not loaded through the fields' types).
  defp raw_rows(schema, repo, fields, opts) do
    batch_size = Keyword.get(opts, :batch_size, 1000)
    [pk] = primary_key!(schema)

    Stream.unfold(:start, fn
      :done ->
        nil

      after_id ->
        query = from(r in schema, order_by: field(r, ^pk), limit: ^batch_size)

        query =
          if after_id == :start, do: query, else: where(query, [r], field(r, ^pk) > ^after_id)

        query = raw_select(query, pk, fields)

        case repo.all(query) do
          [] -> nil
          rows when length(rows) < batch_size -> {rows, :done}
          rows -> {rows, rows |> List.last() |> elem(0)}
        end
    end)
    |> Stream.flat_map(& &1)
  end

  defp raw_select(query, pk, [a]) do
    select(query, [r], {field(r, ^pk), [fragment("?", field(r, ^a))]})
  end

  defp raw_select(query, pk, [a, b]) do
    select(
      query,
      [r],
      {field(r, ^pk), [fragment("?", field(r, ^a)), fragment("?", field(r, ^b))]}
    )
  end

  defp tag(nil, _params), do: nil

  defp tag(raw, params) do
    with {:ok, ciphertext} <- Encrypted.ciphertext(raw, params),
         {:ok, %{tag: tag}} <- Cipher.describe(ciphertext) do
      tag
    else
      _ -> :unreadable
    end
  end

  defp encrypted_fields(schema, opts) do
    all = for f <- schema.__schema__(:fields), encrypted_params(schema, f), do: f
    Keyword.get(opts, :fields, all)
  end

  defp encrypted_params(schema, field) do
    case schema.__schema__(:type, field) do
      {:parameterized, {Encrypted, params}} -> params
      {:parameterized, Encrypted, params} -> params
      _ -> nil
    end
  end

  defp encrypted_params!(schema, field) do
    encrypted_params(schema, field) ||
      raise ArgumentError,
            "#{inspect(field)} of #{inspect(schema)} isn't a Strongbox.Encrypted field"
  end

  defp primary_key!(schema) do
    case schema.__schema__(:primary_key) do
      [_pk] = pk ->
        pk

      _ ->
        raise ArgumentError, "Strongbox.Rotation needs #{inspect(schema)} to have one primary key"
    end
  end
end
