defmodule Strongbox.CipherTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Cloak.Ciphers.AES
  alias Strongbox.{Cipher, Key}

  @k32 :binary.copy(<<1>>, 32)
  @k16 :binary.copy(<<2>>, 16)

  defp key(attrs), do: struct!(Key, Map.merge(%{tag: "k1", key: @k32}, Map.new(attrs)))

  @ciphers [
    {:aes_256_gcm, @k32},
    {:aes_128_gcm, @k16},
    {:aes_256_ccm, @k32},
    {:chacha20_poly1305, @k32}
  ]

  describe "the :strongbox format" do
    test "round-trips with each cipher" do
      for {cipher, k} <- @ciphers,
          plaintext <- ["", "a", "123-45-6789", :binary.copy("é", 500)] do
        keys = [key(cipher: cipher, key: k)]
        ciphertext = Cipher.encrypt(keys, plaintext, [])
        assert <<2, 0, 2, "k1", _::binary>> = ciphertext
        assert Cipher.decrypt(keys, ciphertext, []) == {:ok, plaintext}
      end
    end

    test "never encrypts the same value the same way" do
      keys = [key([])]
      refute Cipher.encrypt(keys, "same", []) == Cipher.encrypt(keys, "same", [])
    end

    property "round-trips any binary, with any context and padding" do
      check all(
              plaintext <- binary(),
              context <- binary(),
              pad <- one_of([constant(nil), integer(1..128)])
            ) do
        keys = [key([])]
        ciphertext = Cipher.encrypt(keys, plaintext, context: context, pad: pad)
        assert Cipher.decrypt(keys, ciphertext, context: context) == {:ok, plaintext}
      end
    end

    test "binds a value to its context" do
      keys = [key([])]
      ciphertext = Cipher.encrypt(keys, "123-45-6789", context: "ssn")

      assert Cipher.decrypt(keys, ciphertext, context: "ssn") == {:ok, "123-45-6789"}
      assert Cipher.decrypt(keys, ciphertext, context: "notes") == :error
      assert Cipher.decrypt(keys, ciphertext, []) == :error
    end

    test "refuses a value with any byte changed" do
      keys = [key([])]
      ciphertext = Cipher.encrypt(keys, "a secret", context: "c", pad: 16)

      for i <- 0..(byte_size(ciphertext) - 1) do
        <<before::binary-size(i), byte, rest::binary>> = ciphertext
        changed = <<before::binary, Bitwise.bxor(byte, 1), rest::binary>>

        assert Cipher.decrypt(keys, changed, context: "c") == :error,
               "byte #{i} changed and it decrypted"
      end
    end

    test "refuses a value cut short or lengthened" do
      keys = [key([])]
      ciphertext = Cipher.encrypt(keys, "a secret", [])

      for size <- 0..(byte_size(ciphertext) - 1) do
        assert Cipher.decrypt(keys, binary_part(ciphertext, 0, size), []) == :error
      end

      assert Cipher.decrypt(keys, ciphertext <> <<0>>, []) == :error
    end

    test "checks the key before decrypting: another key under the same tag fails" do
      ciphertext = Cipher.encrypt([key([])], "a secret", [])
      assert Cipher.decrypt([key(key: :binary.copy(<<7>>, 32))], ciphertext, []) == :error
    end

    test "decrypts with the key the value names" do
      old = key(tag: "old", key: :binary.copy(<<5>>, 32))
      new = key(tag: "new", cipher: :chacha20_poly1305)
      ciphertext = Cipher.encrypt([old], "kept", [])

      assert Cipher.decrypt([new, old], ciphertext, []) == {:ok, "kept"}
      assert Cipher.decrypt([new], ciphertext, []) == :error
    end

    test "pads to a multiple of the block, which hides the length up to it" do
      keys = [key([])]

      sizes =
        for v <- ["", "no", "yes", String.duplicate("x", 62)],
            do: byte_size(Cipher.encrypt(keys, v, pad: 64))

      assert Enum.uniq(sizes) |> length() == 1

      longer = Cipher.encrypt(keys, String.duplicate("x", 64), pad: 64)
      assert byte_size(longer) == hd(sizes) + 64
    end
  end

  describe "the :ecto format" do
    test "round-trips, and writes Ecto.Encrypted's header" do
      for {cipher, k} <- @ciphers do
        keys = [key(format: :ecto, cipher: cipher, key: k)]
        ciphertext = Cipher.encrypt(keys, "hello", context: "ignored")
        assert <<1, 2, "k1", _::binary>> = ciphertext
        assert Cipher.decrypt(keys, ciphertext, []) == {:ok, "hello"}
      end
    end

    test "is Ecto.Encrypted's layout and key derivation" do
      # Ecto.Encrypted: <<1, size, tag, salt::12, iv, ciphertext, tag::16>>,
      # the value key HMAC-SHA256(key, "Ecto.Encrypted" <> salt), the
      # additional data <<1, size, tag>>.
      ciphertext = Cipher.encrypt([key(format: :ecto)], "hello", [])
      <<1, 2, "k1", salt::binary-12, iv::binary-12, rest::binary>> = ciphertext
      body = binary_part(rest, 0, byte_size(rest) - 16)
      auth_tag = binary_part(rest, byte_size(rest), -16)
      value_key = :crypto.mac(:hmac, :sha256, @k32, ["Ecto.Encrypted", salt])

      assert :crypto.crypto_one_time_aead(
               :aes_256_gcm,
               value_key,
               iv,
               body,
               <<1, 2, "k1">>,
               auth_tag,
               false
             ) ==
               "hello"
    end

    test "a :strongbox key reads the :ecto format, so Ecto.Encrypted's data moves over as it is" do
      ciphertext = Cipher.encrypt([key(format: :ecto)], "from ecto", [])
      assert Cipher.decrypt([key([])], ciphertext, []) == {:ok, "from ecto"}
    end

    test "has no padding" do
      assert_raise ArgumentError, ~r/padding needs the :strongbox format/, fn ->
        Cipher.encrypt([key(format: :ecto)], "x", pad: 16)
      end
    end
  end

  describe "values Cloak wrote" do
    test "AES.GCM, with Cloak's default and a configured IV length" do
      for iv_length <- [16, 12] do
        {:ok, ciphertext} =
          AES.GCM.encrypt("from cloak",
            key: @k32,
            tag: "AES.GCM.V1",
            iv_length: iv_length
          )

        keys = [key([]), key(tag: "AES.GCM.V1", format: :cloak, iv_length: iv_length)]
        assert Cipher.decrypt(keys, ciphertext, context: "anything") == {:ok, "from cloak"}
      end
    end

    test "AES.CTR" do
      {:ok, ciphertext} =
        AES.CTR.encrypt("from cloak ctr", key: @k32, tag: "AES.CTR.V1")

      keys = [key([]), key(tag: "AES.CTR.V1", format: :cloak_ctr)]
      assert Cipher.decrypt(keys, ciphertext, []) == {:ok, "from cloak ctr"}
    end

    test "a changed Cloak GCM value fails" do
      {:ok, ciphertext} =
        AES.GCM.encrypt("from cloak", key: @k32, tag: "AES.GCM.V1")

      <<head::binary-size(30), byte, rest::binary>> = ciphertext
      changed = <<head::binary, Bitwise.bxor(byte, 1), rest::binary>>
      assert Cipher.decrypt([key(tag: "AES.GCM.V1", format: :cloak)], changed, []) == :error
    end

    test "Cloak keys only read" do
      assert_raise ArgumentError, ~r/Strongbox only reads/, fn ->
        Cipher.encrypt([key(format: :cloak)], "x", [])
      end
    end
  end

  test "an unknown tag, or something that isn't a value, is an error" do
    keys = [key([])]
    assert Cipher.decrypt(keys, Cipher.encrypt([key(tag: "other")], "x", []), []) == :error
    assert Cipher.decrypt(keys, "plain text", []) == :error
    assert Cipher.decrypt(keys, "", []) == :error
    assert Cipher.decrypt(keys, <<2>>, []) == :error
  end

  test "describe/1 reads the header without a key" do
    assert Cipher.describe(Cipher.encrypt([key(tag: "k9")], "x", [])) ==
             {:ok, %{version: 2, tag: "k9"}}

    assert Cipher.describe(Cipher.encrypt([key(tag: "e1", format: :ecto)], "x", [])) ==
             {:ok, %{version: 1, tag: "e1"}}

    assert Cipher.describe("nope") == :error
  end
end
