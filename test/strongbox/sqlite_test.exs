defmodule Strongbox.SQLiteTest do
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL
  alias Strongbox.{Query, Rotation, TestSQLiteRepo, TestUser, TestVault}

  setup do
    SQL.query!(TestSQLiteRepo, "DELETE FROM users")
    on_exit(&TestVault.reset/0)
  end

  defp insert!(attrs), do: %TestUser{} |> TestUser.changeset(attrs) |> TestSQLiteRepo.insert!()

  test "saves encrypted as a BLOB, loads decrypted, and looks up by a blind index" do
    user = insert!(%{email: "Ana@Example.com", ssn: "123-45-6789", born_on: ~D[1990-05-17]})

    assert %{rows: [["blob", "blob"]]} =
             SQL.query!(TestSQLiteRepo, "SELECT typeof(email), typeof(email_index) FROM users")

    loaded = TestSQLiteRepo.get!(TestUser, user.id)
    assert {loaded.email, loaded.born_on} == {"Ana@Example.com", ~D[1990-05-17]}

    assert TestUser
           |> Query.where_index(:email_index, " ana@example.COM")
           |> TestSQLiteRepo.one()
           |> Map.get(:id) == user.id
  end

  test "rotates keys: rewrites what is stale, and lookups work throughout" do
    users =
      for i <- 1..7,
          do: insert!(%{email: "user#{i}@example.com", ssn: "#{i}", born_on: ~D[2000-01-01]})

    insert!(%{name: "no secrets"})

    Application.put_env(:strongbox, :test_keys, [
      %{tag: "k2", key: :binary.copy(<<2>>, 32)} | TestVault.default_keys()
    ])

    Application.put_env(:strongbox, :test_index_keys, [
      %{tag: "i2", key: :binary.copy(<<8>>, 32)} | TestVault.default_index_keys()
    ])

    assert {:ok, %{rewritten: 21, reindexed: 14, conflicts: 0, unreadable: 0}} =
             Rotation.run(TestSQLiteRepo, TestUser, batch_size: 3)

    assert Rotation.report(TestSQLiteRepo, TestUser).email == %{"k2" => 7, nil => 1}

    # Nothing is left under the old keys: drop them, and all still reads.
    Application.put_env(:strongbox, :test_keys, [%{tag: "k2", key: :binary.copy(<<2>>, 32)}])

    Application.put_env(:strongbox, :test_index_keys, [%{tag: "i2", key: :binary.copy(<<8>>, 32)}])

    for user <- users, do: assert(TestSQLiteRepo.get!(TestUser, user.id).email == user.email)

    assert TestUser
           |> Query.where_index(:email_index, "user5@example.com")
           |> TestSQLiteRepo.one()

    # A second run finds nothing to do.
    assert {:ok, %{rewritten: 0, reindexed: 0, conflicts: 0}} =
             Rotation.run(TestSQLiteRepo, TestUser)
  end
end
