defmodule Strongbox.Query do
  @moduledoc """
  Looking records up by a blind index.
  """

  import Ecto.Query, only: [where: 3]

  @doc """
  Narrows `queryable` to the records whose blind index `field` holds
  `value`, under any index key of the vault, so lookups keep working while
  index keys rotate.

      User
      |> Strongbox.Query.where_index(:email_index, "Jose@Example.com ")
      |> Repo.one()

  The value is normalized as the index normalizes. With `:bytes`, an
  index matches some other values too: check the decrypted value of what
  comes back.
  """
  @spec where_index(Ecto.Queryable.t(), atom, term) :: Ecto.Query.t()
  def where_index(queryable, field, value) do
    query = Ecto.Queryable.to_query(queryable)
    schema = schema!(query)
    hashes = Strongbox.Index.hashes(schema, field, value)

    # As :binary, so the hashes aren't hashed again as the field's own type.
    where(query, [r], type(field(r, ^field), :binary) in ^hashes)
  end

  defp schema!(%Ecto.Query{from: %{source: {_source, schema}}})
       when is_atom(schema) and not is_nil(schema),
       do: schema

  defp schema!(_query), do: raise(ArgumentError, "where_index/3 needs a query on a schema")
end
