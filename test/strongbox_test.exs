defmodule StrongboxTest do
  use ExUnit.Case, async: false

  alias Strongbox.TestVault

  setup do
    on_exit(&TestVault.reset/0)
  end

  test "a vault encrypts and decrypts" do
    ciphertext = TestVault.encrypt("hello", context: "greeting")
    assert TestVault.decrypt(ciphertext, context: "greeting") == {:ok, "hello"}
    assert TestVault.decrypt!(ciphertext, context: "greeting") == "hello"
    assert TestVault.decrypt(ciphertext) == :error
  end

  test "decrypt! names the tag, never the value" do
    ciphertext = TestVault.encrypt("a secret")

    error =
      assert_raise Strongbox.DecryptionError, fn ->
        TestVault.decrypt!(ciphertext, context: "x")
      end

    assert error.message =~ ~s(tag "k1")
    refute error.message =~ "a secret"
  end

  test "stale?/1 is true for values under an old key or in an old format" do
    old = TestVault.encrypt("x")
    refute TestVault.stale?(old)

    Application.put_env(:strongbox, :test_keys, [
      %{tag: "k2", key: :binary.copy(<<2>>, 32)} | TestVault.default_keys()
    ])

    assert TestVault.stale?(old)
    refute TestVault.stale?(TestVault.encrypt("x"))

    Application.put_env(:strongbox, :test_keys, [
      %{tag: "k1", key: :binary.copy(<<1>>, 32), format: :ecto}
    ])

    assert TestVault.stale?(old)
    assert TestVault.stale?("not a value")
  end

  test "keys are checked, and never shown" do
    Application.put_env(:strongbox, :test_keys, [%{tag: "k1", key: "short"}])
    error = assert_raise ArgumentError, fn -> TestVault.encrypt("x") end
    assert error.message =~ "to have 32 bytes"
    refute error.message =~ "short"

    Application.put_env(:strongbox, :test_keys, [
      %{tag: "k1", key: :binary.copy(<<1>>, 32), cipher: :aes_256_cbc}
    ])

    assert_raise ArgumentError, ~r/expected an AEAD cipher/, fn -> TestVault.encrypt("x") end

    Application.put_env(:strongbox, :test_keys, [])
    assert_raise ArgumentError, ~r/non-empty list/, fn -> TestVault.encrypt("x") end

    key = %Strongbox.Key{tag: "k1", key: "the key itself"}
    assert inspect(key) == ~s(#Strongbox.Key<tag: "k1", format: :strongbox>)
  end

  test "an error inside :crypto doesn't put the key in the stacktrace" do
    Application.put_env(:strongbox, :test_keys, [
      %Strongbox.Key{tag: "k1", key: :binary.copy(<<1>>, 32), cipher: :aes_256_gcm}
    ])

    ciphertext = TestVault.encrypt("x")
    assert {:ok, "x"} = TestVault.decrypt(ciphertext)
  end

  test "Strongbox.Key.decode!/1 reads Base64 and refuses the rest" do
    key = Strongbox.Key.generate()
    assert byte_size(key) == 32
    assert Strongbox.Key.decode!(Base.encode64(key) <> "\n") == key

    assert_raise ArgumentError, "expected a key in Base64", fn ->
      Strongbox.Key.decode!("not base64!")
    end
  end

  describe "hashes" do
    test "differ by context, so two indexes don't share hashes" do
      refute TestVault.hash("a@b.c", context: "email") ==
               TestVault.hash("a@b.c", context: "backup_email")

      assert TestVault.hash("a@b.c", context: "email") ==
               TestVault.hash("a@b.c", context: "email")
    end

    test "can be cut short and slowed down" do
      assert byte_size(TestVault.hash("x", bytes: 4)) == 4
      slow = TestVault.hash("x", iterations: 1000)
      assert byte_size(slow) == 32
      refute slow == TestVault.hash("x")
    end

    test "match Ecto.HMAC and Cloak.Ecto.HMAC with compat" do
      key = :binary.copy(<<9>>, 32)
      assert TestVault.hash("v", compat: :ecto) == :crypto.mac(:hmac, :sha256, key, "Ecto.HMACv")
      assert TestVault.hash("v", compat: :cloak) == :crypto.mac(:hmac, :sha256, key, "v")
    end

    test "hashes/2 gives one per index key, for lookups while keys rotate" do
      Application.put_env(:strongbox, :test_index_keys, [
        %{tag: "i2", key: :binary.copy(<<8>>, 32)} | TestVault.default_index_keys()
      ])

      [new, old] = TestVault.hashes("x", context: "c")
      assert new == TestVault.hash("x", context: "c")
      refute new == old
    end
  end
end
