defmodule Strongbox.EctoTest do
  use ExUnit.Case, async: false

  alias Strongbox.{CloakFixtures, TestUser, TestVault}

  setup do
    on_exit(&TestVault.reset/0)
  end

  defp type(module, opts),
    do: Ecto.ParameterizedType.init(module, [field: :f, schema: __MODULE__] ++ opts)

  describe "Strongbox.Encrypted" do
    test "dumps encrypted, bound to the field's name, and loads back" do
      type = type(Strongbox.Encrypted, vault: TestVault)
      {:ok, dumped} = Ecto.Type.dump(type, "123-45-6789")

      assert TestVault.decrypt(dumped, context: "f") == {:ok, "123-45-6789"}
      assert Ecto.Type.load(type, dumped) == {:ok, "123-45-6789"}

      other = type(Strongbox.Encrypted, vault: TestVault, context: "other")
      assert Ecto.Type.load(other, dumped) == :error
    end

    test "holds what :as says" do
      cases = [
        {:string, "olá"},
        {:integer, -42},
        {:float, 1.5},
        {:boolean, false},
        {:date, ~D[1990-05-17]},
        {:time, ~T[09:30:00]},
        {:naive_datetime, ~N[2026-11-25 10:00:00]},
        {:utc_datetime, ~U[2026-11-25 10:00:00Z]},
        {:map, %{"a" => [1, 2], "b" => %{"c" => true}}},
        {{:array, :string}, ["a", "b"]},
        {{:array, :integer}, [1, 2]}
      ]

      for {as, value} <- cases do
        type = type(Strongbox.Encrypted, vault: TestVault, as: as)
        assert {:ok, cast} = Ecto.Type.cast(type, value)
        assert {:ok, dumped} = Ecto.Type.dump(type, cast)
        assert Ecto.Type.load(type, dumped) == {:ok, value}, "as: #{inspect(as)}"
      end
    end

    test "casts as Ecto's own types do" do
      assert Ecto.Type.cast(type(Strongbox.Encrypted, vault: TestVault, as: :integer), "12") ==
               {:ok, 12}

      assert Ecto.Type.cast(type(Strongbox.Encrypted, vault: TestVault, as: :date), "2026-01-02") ==
               {:ok, ~D[2026-01-02]}

      assert Ecto.Type.cast(type(Strongbox.Encrypted, vault: TestVault), 12) == :error

      assert {:error, _} =
               Ecto.Type.dump(type(Strongbox.Encrypted, vault: TestVault, as: :string), <<255>>)
               |> wrap()
    end

    test "nil stays nil" do
      type = type(Strongbox.Encrypted, vault: TestVault)
      assert Ecto.Type.dump(type, nil) == {:ok, nil}
      assert Ecto.Type.load(type, nil) == {:ok, nil}
    end

    test "keeps the encrypted bytes as Base64 with encoding: :base64" do
      type = type(Strongbox.Encrypted, vault: TestVault, encoding: :base64)
      assert Ecto.Type.type(type) == :string
      {:ok, dumped} = Ecto.Type.dump(type, "x")
      assert {:ok, _} = Base.decode64(dumped)
      assert Ecto.Type.load(type, dumped) == {:ok, "x"}
    end

    test "loads values Cloak.Ecto wrote" do
      Application.put_env(:strongbox, :test_keys, [
        %{tag: "k1", key: :binary.copy(<<1>>, 32)},
        %{tag: "AES.GCM.V1", key: CloakFixtures.key(), format: :cloak}
      ])

      for {name, as, value} <- [
            {"binary", :binary, "x"},
            {"integer", :integer, 42},
            {"float", :float, 1.5},
            {"decimal", :decimal, Decimal.new("12.50")},
            {"time", :time, ~T[09:30:00]},
            {"integer_list", {:array, :integer}, [1, 2]},
            {"date", :date, ~D[1990-05-17]},
            {"naive_datetime", :naive_datetime, ~N[2026-11-25 10:00:00]},
            {"utc_datetime", :utc_datetime, ~U[2026-11-25 10:00:00Z]},
            {"map", :map, %{"a" => 1}}
          ] do
        {_text, ciphertext} = CloakFixtures.value(name)
        type = type(Strongbox.Encrypted, vault: TestVault, as: as)
        assert Ecto.Type.load(type, ciphertext) == {:ok, value}, "as: #{inspect(as)}"
      end
    end

    test "checks its options" do
      assert_raise ArgumentError, ~r/expected a :vault/, fn -> type(Strongbox.Encrypted, []) end

      assert_raise ArgumentError, ~r/unknown :as/, fn ->
        type(Strongbox.Encrypted, vault: TestVault, as: :uuid)
      end

      assert_raise ArgumentError, ~r/:pad/, fn ->
        type(Strongbox.Encrypted, vault: TestVault, pad: 0)
      end

      assert_raise ArgumentError, ~r/:encoding/, fn ->
        type(Strongbox.Encrypted, vault: TestVault, encoding: :hex)
      end
    end
  end

  describe "Strongbox.Index" do
    test "dumps the normalized value's hash, under the index's own key" do
      type = type(Strongbox.Index, vault: TestVault, normalize: [:trim, :downcase])
      {:ok, a} = Ecto.Type.dump(type, " Jose@Example.com ")
      {:ok, b} = Ecto.Type.dump(type, "jose@example.com")
      assert a == b
      assert a == TestVault.hash("jose@example.com", context: "f")
    end

    test "normalizers" do
      dump = fn normalize, value ->
        {:ok, hash} =
          Ecto.Type.dump(type(Strongbox.Index, vault: TestVault, normalize: normalize), value)

        hash
      end

      assert dump.([:digits], "+351 912-345-678") == dump.([:digits], "351912345678")
      assert dump.([:squish], "a   b\n c") == dump.([:squish], "a b c")
      assert dump.([:nfc], "é") == dump.([:nfc], "é")
      assert dump.([{String, :reverse}], "abc") == dump.([], "cba")
    end

    test "loads the stored hash as it is" do
      type = type(Strongbox.Index, vault: TestVault)
      assert Ecto.Type.load(type, <<1, 2, 3>>) == {:ok, <<1, 2, 3>>}
    end

    test "checks its options" do
      assert_raise ArgumentError, ~r/unknown normalizer/, fn ->
        type(Strongbox.Index, vault: TestVault, normalize: [:nope])
      end

      assert_raise ArgumentError, ~r/:bytes/, fn ->
        type(Strongbox.Index, vault: TestVault, bytes: 0)
      end

      assert_raise ArgumentError, ~r/:compat/, fn ->
        type(Strongbox.Index, vault: TestVault, compat: :rails)
      end
    end
  end

  describe "Strongbox.Schema" do
    test "redacts encrypted fields and indexes" do
      user = %TestUser{
        name: "Ana",
        email: "ana@example.com",
        ssn: "123",
        email_index: "ana@example.com"
      }

      inspected = inspect(user)

      assert inspected =~ "Ana"
      refute inspected =~ "ana@example.com"
      refute inspected =~ "123"

      assert TestUser.__schema__(:redact_fields) |> Enum.sort() ==
               [:born_on, :email, :email_index, :notes, :ssn, :ssn_index]
    end

    test "gives each field the vault and its options" do
      assert {:parameterized,
              {Strongbox.Encrypted, %{vault: TestVault, as: :date, context: "born_on"}}} =
               TestUser.__schema__(:type, :born_on)

      assert {:parameterized, {Strongbox.Index, %{of: :ssn, bytes: 8}}} =
               TestUser.__schema__(:type, :ssn_index)
    end
  end

  describe "Strongbox.Changeset.put_indexes/2" do
    test "copies changed fields into their indexes" do
      changeset = TestUser.changeset(%TestUser{}, %{email: "Ana@Example.com", name: "Ana"})
      assert Ecto.Changeset.get_change(changeset, :email_index) == "Ana@Example.com"
      refute Map.has_key?(changeset.changes, :ssn_index)
    end

    test "leaves unchanged fields' indexes, unless forced" do
      user = %TestUser{email: "ana@example.com", ssn: "1"}
      changeset = Ecto.Changeset.change(user) |> Strongbox.Changeset.put_indexes()
      assert changeset.changes == %{}

      forced = Ecto.Changeset.change(user) |> Strongbox.Changeset.put_indexes(force: true)
      assert forced.changes == %{email_index: "ana@example.com", ssn_index: "1"}
    end

    test "a field set to nil empties its index" do
      changeset = TestUser.changeset(%TestUser{email: "a@b.c", email_index: <<1>>}, %{email: nil})
      assert Ecto.Changeset.fetch_change(changeset, :email_index) == {:ok, nil}
    end
  end

  defp wrap(:error), do: {:error, :error}
  defp wrap(other), do: other
end
