defmodule Strongbox.TestVault do
  @moduledoc false
  # Keys from the application env, so tests can rotate them.
  use Strongbox

  @impl true
  def keys, do: Application.fetch_env!(:strongbox, :test_keys)

  @impl true
  def index_keys, do: Application.fetch_env!(:strongbox, :test_index_keys)

  def default_keys, do: [%{tag: "k1", key: :binary.copy(<<1>>, 32)}]
  def default_index_keys, do: [%{tag: "i1", key: :binary.copy(<<9>>, 32)}]

  def reset do
    Application.put_env(:strongbox, :test_keys, default_keys())
    Application.put_env(:strongbox, :test_index_keys, default_index_keys())
  end
end

defmodule Strongbox.TestRepo do
  @moduledoc false
  use Ecto.Repo, otp_app: :strongbox, adapter: Ecto.Adapters.Postgres
end

defmodule Strongbox.TestUser do
  @moduledoc false
  use Ecto.Schema
  use Strongbox.Schema, vault: Strongbox.TestVault

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "users" do
    field :name, :string
    encrypted_field :email, as: :string
    encrypted_field :ssn
    encrypted_field :born_on, as: :date
    encrypted_field :notes, as: :map, pad: 64
    blind_index :email_index, of: :email, normalize: [:trim, :downcase]
    blind_index :ssn_index, of: :ssn, normalize: [:digits], bytes: 8
  end

  def changeset(user, attrs) do
    user
    |> Ecto.Changeset.cast(attrs, [:name, :email, :ssn, :born_on, :notes])
    |> Strongbox.Changeset.put_indexes()
  end
end
