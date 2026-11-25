defmodule Strongbox.DBTest do
  use ExUnit.Case, async: false

  @moduletag :db

  import Ecto.Query

  alias Cloak.Ciphers.AES
  alias Ecto.Adapters.SQL
  alias Strongbox.{Query, Rotation, TestRepo, TestUser, TestVault}

  setup do
    :ok = SQL.Sandbox.checkout(TestRepo)
    on_exit(&TestVault.reset/0)
  end

  defp insert!(attrs), do: %TestUser{} |> TestUser.changeset(attrs) |> TestRepo.insert!()

  defp raw(id, column) do
    %{rows: [[value]]} =
      SQL.query!(TestRepo, "SELECT #{column} FROM users WHERE id = $1", [
        Ecto.UUID.dump!(id)
      ])

    value
  end

  test "saves encrypted, loads decrypted" do
    user =
      insert!(%{
        name: "Ana",
        email: "ana@example.com",
        ssn: "123-45-6789",
        born_on: ~D[1990-05-17],
        notes: %{"allergies" => ["penicillin"]}
      })

    assert <<2, _::binary>> = raw(user.id, "email")
    refute raw(user.id, "email") =~ "ana"

    loaded = TestRepo.get!(TestUser, user.id)
    assert loaded.email == "ana@example.com"
    assert loaded.ssn == "123-45-6789"
    assert loaded.born_on == ~D[1990-05-17]
    assert loaded.notes == %{"allergies" => ["penicillin"]}
    assert byte_size(loaded.email_index) == 32
    assert byte_size(loaded.ssn_index) == 8
  end

  test "a value copied into another column doesn't decrypt there" do
    user = insert!(%{email: "ana@example.com", ssn: "123-45-6789"})
    SQL.query!(TestRepo, "UPDATE users SET ssn = email")

    assert_raise ArgumentError, ~r/cannot load/, fn -> TestRepo.get!(TestUser, user.id) end
  end

  test "looks records up by a blind index, normalized" do
    user = insert!(%{email: "Ana@Example.com"})
    insert!(%{email: "other@example.com"})

    assert TestUser
           |> Query.where_index(:email_index, " ana@example.COM")
           |> TestRepo.one()
           |> Map.get(:id) ==
             user.id

    assert TestUser |> Query.where_index(:email_index, "nobody@example.com") |> TestRepo.all() ==
             []

    # Under the first index key, as a plain comparison too.
    assert TestRepo.one(
             from(u in TestUser, where: u.email_index == ^"ana@example.com", select: u.id)
           ) == user.id
  end

  test "a unique index on a blind index refuses the same value twice" do
    insert!(%{email: "ana@example.com"})

    assert {:error, changeset} =
             %TestUser{}
             |> TestUser.changeset(%{email: "ANA@example.com"})
             |> Ecto.Changeset.unique_constraint(:email_index)
             |> TestRepo.insert()

    assert changeset.errors[:email_index]
  end

  test "rotates keys: reports, rewrites what is stale, and lookups work throughout" do
    users =
      for i <- 1..7,
          do: insert!(%{email: "user#{i}@example.com", ssn: "#{i}", born_on: ~D[2000-01-01]})

    insert!(%{name: "no secrets"})

    assert Rotation.report(TestRepo, TestUser).email == %{"k1" => 7, nil => 1}

    # A new encryption key and a new index key, the old ones kept after them.
    Application.put_env(:strongbox, :test_keys, [
      %{tag: "k2", key: :binary.copy(<<2>>, 32), cipher: :chacha20_poly1305}
      | TestVault.default_keys()
    ])

    Application.put_env(:strongbox, :test_index_keys, [
      %{tag: "i2", key: :binary.copy(<<8>>, 32)} | TestVault.default_index_keys()
    ])

    # Old values still load and are still found.
    assert TestRepo.get!(TestUser, hd(users).id).email == "user1@example.com"
    assert TestUser |> Query.where_index(:email_index, "user3@example.com") |> TestRepo.one()

    assert {:ok, %{rewritten: 21, reindexed: 14, conflicts: 0, unreadable: 0}} =
             Rotation.run(TestRepo, TestUser, batch_size: 3)

    assert Rotation.report(TestRepo, TestUser).email == %{"k2" => 7, nil => 1}
    assert Rotation.report(TestRepo, TestUser).notes == %{nil => 8}

    # Nothing is left under the old keys: drop them, and all still reads.
    Application.put_env(:strongbox, :test_keys, [
      %{tag: "k2", key: :binary.copy(<<2>>, 32), cipher: :chacha20_poly1305}
    ])

    Application.put_env(:strongbox, :test_index_keys, [%{tag: "i2", key: :binary.copy(<<8>>, 32)}])

    for user <- users, do: assert(TestRepo.get!(TestUser, user.id).email == user.email)
    assert TestUser |> Query.where_index(:email_index, "user5@example.com") |> TestRepo.one()
    assert TestUser |> Query.where_index(:ssn_index, "5") |> TestRepo.one()

    # A second run finds nothing to do.
    assert {:ok, %{rewritten: 0, reindexed: 0}} = Rotation.run(TestRepo, TestUser)
  end

  test "rotation leaves a row changed meanwhile as it is" do
    user = insert!(%{email: "ana@example.com"})

    Application.put_env(:strongbox, :test_keys, [
      %{tag: "k2", key: :binary.copy(<<2>>, 32)} | TestVault.default_keys()
    ])

    defmodule ConflictRepo do
      # Writes to the row just before rotation's own write, as the app would.
      def all(query), do: TestRepo.all(query)

      def update_all(query, updates) do
        if Process.get(:changed_meanwhile) == nil do
          Process.put(:changed_meanwhile, true)
          [id] = TestRepo.all(from(u in TestUser, select: u.id))

          TestRepo.get!(TestUser, id)
          |> TestUser.changeset(%{email: "new@example.com"})
          |> TestRepo.update!()
        end

        TestRepo.update_all(query, updates)
      end
    end

    assert {:ok, %{rewritten: 0, conflicts: 1}} =
             Rotation.run(ConflictRepo, TestUser, indexes: false)

    assert TestRepo.get!(TestUser, user.id).email == "new@example.com"
  end

  test "rotation counts values no key decrypts, and leaves them" do
    user = insert!(%{email: "ana@example.com"})

    SQL.query!(TestRepo, "UPDATE users SET ssn = '\\x0102'::bytea WHERE id = $1", [
      Ecto.UUID.dump!(user.id)
    ])

    assert Rotation.report(TestRepo, TestUser, fields: [:ssn]) == %{ssn: %{:unreadable => 1}}

    assert {:ok, %{unreadable: 1}} =
             Rotation.run(TestRepo, TestUser, fields: [:ssn], indexes: false)
  end

  test "moves a table Cloak encrypted over to Strongbox, by rotation" do
    cloak_key = :binary.copy(<<3>>, 32)
    id = Ecto.UUID.generate()

    {:ok, email} = AES.GCM.encrypt("ana@example.com", key: cloak_key, tag: "AES.GCM.V1")
    {:ok, born_on} = AES.GCM.encrypt(to_string(~D[1990-05-17]), key: cloak_key, tag: "AES.GCM.V1")
    hash = :crypto.mac(:hmac, :sha256, :binary.copy(<<9>>, 32), "ana@example.com")

    SQL.query!(
      TestRepo,
      "INSERT INTO users (id, email, born_on, email_index) VALUES ($1, $2, $3, $4)",
      [Ecto.UUID.dump!(id), email, born_on, hash]
    )

    Application.put_env(:strongbox, :test_keys, [
      %{tag: "k1", key: :binary.copy(<<1>>, 32)},
      %{tag: "AES.GCM.V1", key: cloak_key, format: :cloak}
    ])

    user = TestRepo.get!(TestUser, id)
    assert {user.email, user.born_on} == {"ana@example.com", ~D[1990-05-17]}

    assert Rotation.report(TestRepo, TestUser, fields: [:email]) == %{email: %{"AES.GCM.V1" => 1}}

    assert {:ok, %{rewritten: 2, unreadable: 0}} =
             Rotation.run(TestRepo, TestUser, indexes: false)

    assert Rotation.report(TestRepo, TestUser, fields: [:email]) == %{email: %{"k1" => 1}}

    # Now bound to its field, readable without the Cloak key.
    Application.put_env(:strongbox, :test_keys, TestVault.default_keys())
    assert <<2, _::binary>> = raw(id, "email")
    assert TestRepo.get!(TestUser, id).email == "ana@example.com"
  end
end
