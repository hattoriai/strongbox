defmodule Strongbox.Schema do
  @moduledoc """
  Encrypted fields and blind indexes in a schema, always redacted.

      defmodule MyApp.User do
        use Ecto.Schema
        use Strongbox.Schema, vault: MyApp.Vault

        schema "users" do
          field :name, :string
          encrypted_field :email, as: :string
          encrypted_field :born_on, as: :date
          blind_index :email_index, of: :email, normalize: [:trim, :downcase]
        end
      end

  `encrypted_field/2` is `field(name, Strongbox.Encrypted, opts)` and
  `blind_index/2` is `field(name, Strongbox.Index, opts)`, each with the
  vault given to `use` and `redact: true`, so the values never show when
  the struct is inspected. Options are those of `Strongbox.Encrypted` and
  `Strongbox.Index`; a `:vault` among them takes the place of the one
  given to `use`.
  """

  @doc false
  defmacro __using__(opts) do
    quote do
      import Strongbox.Schema, only: [encrypted_field: 1, encrypted_field: 2, blind_index: 2]
      Module.put_attribute(__MODULE__, :strongbox_vault, Keyword.get(unquote(opts), :vault))
    end
  end

  @doc """
  An encrypted field: see `Strongbox.Encrypted` for its options.
  """
  defmacro encrypted_field(name, opts \\ []) do
    quote do
      Ecto.Schema.field(
        unquote(name),
        Strongbox.Encrypted,
        Strongbox.Schema.__opts__(@strongbox_vault, unquote(opts))
      )
    end
  end

  @doc """
  A blind index of an encrypted field: see `Strongbox.Index` for its
  options. `:of` names the field it indexes.
  """
  defmacro blind_index(name, opts) do
    quote do
      Ecto.Schema.field(
        unquote(name),
        Strongbox.Index,
        Strongbox.Schema.__opts__(@strongbox_vault, unquote(opts))
      )
    end
  end

  @doc false
  def __opts__(vault, opts) do
    [vault: vault] |> Keyword.merge(opts) |> Keyword.put(:redact, true)
  end
end
