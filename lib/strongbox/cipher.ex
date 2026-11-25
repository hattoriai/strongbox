defmodule Strongbox.Cipher do
  @moduledoc false
  # The formats of encrypted values. The [format](format.md) guide describes
  # each byte; keep the two in step.
  #
  # Strongbox (version 2):
  #
  #   <<2, flags, tag_size, tag, salt::12, commitment::16, iv, ciphertext, auth_tag::16>>
  #
  #   The value's key and its commitment come from the key and the salt:
  #     prk        = HMAC-SHA256(key, "Strongbox v2" <> salt)
  #     value_key  = HMAC-SHA256(prk, "key" <> <<1>>), cut to the cipher's key length
  #     commitment = HMAC-SHA256(prk, "commitment" <> <<1>>), cut to 16 bytes
  #   The additional data is the header up to the tag, then the context:
  #     <<2, flags, tag_size, tag>> <> context
  #   flags: bit 0, the plaintext ends in padding (0x80 then zeros).
  #
  # Ecto (version 1), as Ecto.Encrypted writes it:
  #
  #   <<1, tag_size, tag, salt::12, iv, ciphertext, auth_tag::16>>
  #     value_key = HMAC-SHA256(key, "Ecto.Encrypted" <> salt), cut to the key length
  #     additional data: <<1, tag_size, tag>>
  #
  # Cloak (read only), as Cloak.Ciphers.AES.GCM and AES.CTR write it, for
  # tags shorter than 128 bytes:
  #
  #   GCM: <<1, tag_size, tag, iv::iv_length, auth_tag::16, ciphertext>>,
  #        AES-256-GCM with the key itself and the additional data "AES256GCM"
  #   CTR: <<1, tag_size, tag, iv::16, ciphertext>>, AES-256-CTR, no authentication

  alias Strongbox.Key

  @salt_size 12
  @auth_tag_size 16
  @commitment_size 16
  @flag_padded 1

  @doc false
  # Encrypts with the first key. Options: :context (a binary, bound to the
  # value; ignored in the :ecto format, which has no place for it) and :pad
  # (a block size: the plaintext is padded to a multiple of it).
  @spec encrypt([Key.t(), ...], binary, keyword) :: binary
  def encrypt([%Key{format: :strongbox} = key | _], plaintext, opts) do
    context = Keyword.get(opts, :context, "")
    {plaintext, flags} = pad(plaintext, Keyword.get(opts, :pad))
    %{key_length: key_length, iv_length: iv_length} = :crypto.cipher_info(key.cipher)

    <<salt::binary-size(@salt_size), iv::binary-size(^iv_length)>> =
      :crypto.strong_rand_bytes(@salt_size + iv_length)

    {value_key, commitment} = derive(key.key, salt, key_length)
    header = <<2, flags, byte_size(key.tag), key.tag::binary>>

    {ciphertext, auth_tag} =
      :crypto.crypto_one_time_aead(
        key.cipher,
        value_key,
        iv,
        plaintext,
        [header, context],
        @auth_tag_size,
        true
      )

    IO.iodata_to_binary([header, salt, commitment, iv, ciphertext, auth_tag])
  rescue
    e -> reraise e, prune(__STACKTRACE__)
  end

  def encrypt([%Key{format: :ecto} = key | _], plaintext, opts) do
    if Keyword.get(opts, :pad) do
      raise ArgumentError,
            "padding needs the :strongbox format, the key #{inspect(key.tag)} is :ecto"
    end

    %{key_length: key_length, iv_length: iv_length} = :crypto.cipher_info(key.cipher)

    <<salt::binary-size(@salt_size), iv::binary-size(^iv_length)>> =
      :crypto.strong_rand_bytes(@salt_size + iv_length)

    value_key = ecto_value_key(key.key, salt, key_length)
    aad = <<1, byte_size(key.tag), key.tag::binary>>

    {ciphertext, auth_tag} =
      :crypto.crypto_one_time_aead(
        key.cipher,
        value_key,
        iv,
        plaintext,
        aad,
        @auth_tag_size,
        true
      )

    IO.iodata_to_binary([aad, salt, iv, ciphertext, auth_tag])
  rescue
    e -> reraise e, prune(__STACKTRACE__)
  end

  def encrypt([%Key{format: format, tag: tag} | _], _plaintext, _opts) do
    raise ArgumentError,
          "the first key encrypts, and #{inspect(tag)} is a #{inspect(format)} key, " <>
            "which Strongbox only reads: put a :strongbox key first"
  end

  @doc false
  # Decrypts with the key the value names. Returns :error when no key has its
  # tag, when it was changed, or when its context isn't the one given.
  @spec decrypt([Key.t(), ...], binary, keyword) :: {:ok, binary} | :error
  def decrypt(keys, <<2, flags, size, tag::binary-size(size), rest::binary>>, opts) do
    with %Key{format: format} = key when format in [:strongbox, :ecto] <- find(keys, tag),
         %{key_length: key_length, iv_length: iv_length} = :crypto.cipher_info(key.cipher),
         ciphertext_size =
           byte_size(rest) - @salt_size - @commitment_size - iv_length - @auth_tag_size,
         true <- ciphertext_size >= 0,
         <<salt::binary-size(@salt_size), commitment::binary-size(@commitment_size),
           iv::binary-size(^iv_length), ciphertext::binary-size(^ciphertext_size),
           auth_tag::binary-size(@auth_tag_size)>> <- rest,
         {value_key, expected} = derive(key.key, salt, key_length),
         true <- :crypto.hash_equals(commitment, expected),
         header = <<2, flags, size, tag::binary>>,
         context = Keyword.get(opts, :context, ""),
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(
             key.cipher,
             value_key,
             iv,
             ciphertext,
             [header, context],
             auth_tag,
             false
           ) do
      unpad(plaintext, flags)
    else
      _ -> :error
    end
  rescue
    e -> reraise e, prune(__STACKTRACE__)
  end

  def decrypt(keys, <<1, size, tag::binary-size(size), rest::binary>>, _opts) do
    case find(keys, tag) do
      %Key{format: format} = key when format in [:strongbox, :ecto] ->
        decrypt_ecto(key, size, rest)

      %Key{format: :cloak} = key ->
        decrypt_cloak(key, rest)

      %Key{format: :cloak_ctr} = key ->
        decrypt_cloak_ctr(key, rest)

      nil ->
        :error
    end
  rescue
    e -> reraise e, prune(__STACKTRACE__)
  end

  def decrypt(_keys, _binary, _opts), do: :error

  @doc false
  # The tag and the format of a value, read from its header without a key.
  @spec describe(binary) :: {:ok, %{version: 1 | 2, tag: binary}} | :error
  def describe(<<2, _flags, size, tag::binary-size(size), _rest::binary>>),
    do: {:ok, %{version: 2, tag: tag}}

  def describe(<<1, size, tag::binary-size(size), _rest::binary>>),
    do: {:ok, %{version: 1, tag: tag}}

  def describe(_binary), do: :error

  defp decrypt_ecto(key, size, rest) do
    %{key_length: key_length, iv_length: iv_length} = :crypto.cipher_info(key.cipher)
    ciphertext_size = byte_size(rest) - @salt_size - iv_length - @auth_tag_size

    with true <- ciphertext_size >= 0,
         <<salt::binary-size(@salt_size), iv::binary-size(^iv_length),
           ciphertext::binary-size(^ciphertext_size), auth_tag::binary-size(@auth_tag_size)>> <-
           rest,
         value_key = ecto_value_key(key.key, salt, key_length),
         aad = <<1, size, key.tag::binary>>,
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(
             key.cipher,
             value_key,
             iv,
             ciphertext,
             aad,
             auth_tag,
             false
           ) do
      {:ok, plaintext}
    else
      _ -> :error
    end
  end

  defp decrypt_cloak(key, rest) do
    iv_length = key.iv_length

    with <<iv::binary-size(^iv_length), auth_tag::binary-size(16), ciphertext::binary>> <- rest,
         plaintext when is_binary(plaintext) <-
           :crypto.crypto_one_time_aead(
             :aes_256_gcm,
             key.key,
             iv,
             ciphertext,
             "AES256GCM",
             auth_tag,
             false
           ) do
      {:ok, plaintext}
    else
      _ -> :error
    end
  end

  defp decrypt_cloak_ctr(key, <<iv::binary-size(16), ciphertext::binary>>) do
    {:ok, :crypto.crypto_one_time(:aes_256_ctr, key.key, iv, ciphertext, false)}
  end

  defp decrypt_cloak_ctr(_key, _rest), do: :error

  defp find(keys, tag), do: Enum.find(keys, &(&1.tag == tag))

  defp derive(key, salt, key_length) do
    prk = :crypto.mac(:hmac, :sha256, key, ["Strongbox v2", salt])

    <<value_key::binary-size(^key_length), _::binary>> =
      :crypto.mac(:hmac, :sha256, prk, ["key", 1])

    <<commitment::binary-size(@commitment_size), _::binary>> =
      :crypto.mac(:hmac, :sha256, prk, ["commitment", 1])

    {value_key, commitment}
  end

  defp ecto_value_key(key, salt, key_length) do
    <<value_key::binary-size(^key_length), _::binary>> =
      :crypto.mac(:hmac, :sha256, key, ["Ecto.Encrypted", salt])

    value_key
  end

  # Padding: 0x80, then zeros up to a multiple of the block, which hides a
  # value's length up to the block. A value always gets at least the 0x80.
  defp pad(plaintext, nil), do: {plaintext, 0}

  defp pad(plaintext, block) when is_integer(block) and block > 0 do
    zeros = rem(block - rem(byte_size(plaintext) + 1, block), block)
    {[plaintext, 0x80, :binary.copy(<<0>>, zeros)] |> IO.iodata_to_binary(), @flag_padded}
  end

  defp unpad(plaintext, flags) when Bitwise.band(flags, @flag_padded) == 0, do: {:ok, plaintext}

  defp unpad(plaintext, _flags), do: unpad_at(plaintext, byte_size(plaintext) - 1)

  defp unpad_at(_plaintext, -1), do: :error

  defp unpad_at(plaintext, at) do
    case :binary.at(plaintext, at) do
      0 -> unpad_at(plaintext, at - 1)
      0x80 -> {:ok, binary_part(plaintext, 0, at)}
      _ -> :error
    end
  end

  # Takes the arguments out of the top frame of a stacktrace, so a key given
  # to :crypto never reaches an error report. Only the top frame has them.
  defp prune([{mod, fun, [_ | _] = args, info} | rest]),
    do: [{mod, fun, length(args), info} | rest]

  defp prune(stacktrace), do: stacktrace
end
