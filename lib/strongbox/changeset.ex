defmodule Strongbox.Changeset do
  @moduledoc """
  Blind indexes kept in step with the fields they index.

      def changeset(user, attrs) do
        user
        |> cast(attrs, [:email])
        |> validate_required([:email])
        |> Strongbox.Changeset.put_indexes()
        |> unique_constraint(:email_index)
      end
  """

  alias Strongbox.Index

  @doc """
  Copies the value of each changed field into the blind indexes whose
  `:of` names it, where it is hashed when the changeset is saved.

  A field changed to `nil` leaves its index `nil`. Indexes whose field
  didn't change are left as they are; pass `force: true` to copy every
  indexed field, as `Strongbox.Rotation` does to hash under a new key.
  """
  @spec put_indexes(Ecto.Changeset.t(), keyword) :: Ecto.Changeset.t()
  def put_indexes(%Ecto.Changeset{data: %schema{}} = changeset, opts \\ []) do
    force = Keyword.get(opts, :force, false)

    Enum.reduce(indexes(schema), changeset, fn {index, of}, changeset ->
      case Ecto.Changeset.fetch_change(changeset, of) do
        {:ok, value} ->
          Ecto.Changeset.force_change(changeset, index, value)

        :error when force ->
          Ecto.Changeset.force_change(changeset, index, Ecto.Changeset.get_field(changeset, of))

        :error ->
          changeset
      end
    end)
  end

  @doc false
  # The blind indexes of a schema that name their field: [{index, of}].
  @spec indexes(module) :: [{atom, atom}]
  def indexes(schema) do
    for field <- schema.__schema__(:fields),
        params = Index.params(schema, field),
        params.of != nil,
        do: {field, params.of}
  end
end
