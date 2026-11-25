defmodule Strongbox.Key do
  @moduledoc """
  A key of a vault, with the tag that names it in each value it encrypts.

  A vault's `c:Strongbox.keys/0` and `c:Strongbox.index_keys/0` may return
  maps or these structs; Strongbox turns maps into structs and checks them.
  Inspecting a key never shows its bytes, so a key in a log or an error
  report gives away only its tag.

  ## Fields

    * `:tag` - a binary of 1 to 127 bytes, written in front of each value
      the key encrypts, so the right key is found to decrypt it.
    * `:key` - the key itself, as a binary.
    * `:cipher` - for encryption keys, an AEAD cipher of `:crypto`:
      `:aes_256_gcm` (the default), `:aes_128_gcm`, `:aes_256_ccm` or
      `:chacha20_poly1305`.
    * `:format` - how values under this key are written and read:
      `:strongbox` (the default), `:ecto` (as `Ecto.Encrypted`), or, to read
      values Cloak wrote, `:cloak` (Cloak's AES.GCM) or `:cloak_ctr`
      (Cloak's AES.CTR). See the [format](format.md) guide.
    * `:iv_length` - for `:cloak` keys only, the length of Cloak's IVs:
      16 unless the Cloak vault was given another `:iv_length`.
    * `:algorithm` - for index keys, the hash of the HMAC: `:sha256` (the
      default), `:sha384`, `:sha512`, `:sha3_256` and so on.

  ## Making a key

      $ mix strongbox.gen.key

  prints a new random key in Base64. Keep it in an environment variable
  and read it in `config/runtime.exs` with `decode!/1`.
  """

  @enforce_keys [:tag, :key]
  defstruct [
    :tag,
    :key,
    cipher: :aes_256_gcm,
    format: :strongbox,
    iv_length: 16,
    algorithm: :sha256
  ]

  @type format :: :strongbox | :ecto | :cloak | :cloak_ctr

  @type t :: %__MODULE__{
          tag: binary,
          key: binary,
          cipher: atom,
          format: format,
          iv_length: pos_integer,
          algorithm: atom
        }

  @formats [:strongbox, :ecto, :cloak, :cloak_ctr]

  @doc """
  Returns `bytes` random bytes, 32 by default: a new key.
  """
  @spec generate(pos_integer) :: binary
  def generate(bytes \\ 32), do: :crypto.strong_rand_bytes(bytes)

  @doc """
  Decodes a key kept in Base64, as `mix strongbox.gen.key` prints it.

  Raises `ArgumentError` without the value if it isn't Base64.
  """
  @spec decode!(binary) :: binary
  def decode!(base64) when is_binary(base64) do
    case Base.decode64(String.trim(base64)) do
      {:ok, key} -> key
      :error -> raise ArgumentError, "expected a key in Base64"
    end
  end

  @doc false
  # Turns a vault's encryption keys into checked structs.
  @spec encryption_keys!(module, term) :: [t, ...]
  def encryption_keys!(vault, [_ | _] = keys), do: Enum.map(keys, &encryption_key!(vault, &1))

  def encryption_keys!(vault, _keys) do
    raise ArgumentError, "expected #{inspect(vault)}.keys/0 to return a non-empty list of keys"
  end

  @doc false
  @spec index_keys!(module, term) :: [t, ...]
  def index_keys!(vault, [_ | _] = keys), do: Enum.map(keys, &index_key!(vault, &1))

  def index_keys!(vault, _keys) do
    raise ArgumentError,
          "expected #{inspect(vault)}.index_keys/0 to return a non-empty list of keys"
  end

  defp encryption_key!(vault, key) do
    %__MODULE__{} = key = to_key!(vault, key)

    unless key.format in @formats do
      raise ArgumentError,
            "unknown format #{inspect(key.format)} for #{name(vault, key)}, " <>
              "expected one of #{inspect(@formats)}"
    end

    cipher = if key.format in [:cloak, :cloak_ctr], do: cloak_cipher(key), else: key.cipher
    info = cipher_info!(vault, key, cipher)

    if key.format != :cloak_ctr and not info.prop_aead do
      raise ArgumentError,
            "expected an AEAD cipher for #{name(vault, key)}, got: #{inspect(key.cipher)}"
    end

    # Value keys are derived with HMAC-SHA256, which gives 32 bytes.
    if info.key_length > 32 do
      raise ArgumentError,
            "unsupported cipher #{inspect(cipher)} for #{name(vault, key)}: " <>
              "keys longer than 32 bytes are not supported"
    end

    if byte_size(key.key) != info.key_length do
      raise ArgumentError,
            "expected #{name(vault, key)} to have #{info.key_length} bytes " <>
              "for #{inspect(cipher)}, got: #{byte_size(key.key)} bytes"
    end

    %{key | cipher: cipher}
  end

  defp index_key!(vault, key) do
    %__MODULE__{} = key = to_key!(vault, key)

    size =
      try do
        :crypto.hash_info(key.algorithm).size
      rescue
        ArgumentError ->
          reraise ArgumentError,
                  [
                    message: "unknown algorithm #{inspect(key.algorithm)} for #{name(vault, key)}"
                  ],
                  __STACKTRACE__
      end

    # RFC 2104: a key of at least the hash's size.
    if byte_size(key.key) < size do
      raise ArgumentError,
            "expected #{name(vault, key)} to have at least #{size} bytes " <>
              "for #{inspect(key.algorithm)}, got: #{byte_size(key.key)} bytes"
    end

    key
  end

  defp to_key!(vault, %__MODULE__{} = key), do: check_shape!(vault, key)
  defp to_key!(vault, %{} = map), do: check_shape!(vault, struct(__MODULE__, map))

  defp to_key!(vault, _other) do
    raise ArgumentError,
          "expected each key of #{inspect(vault)} to be a map with :tag (a binary of 1 to 127 " <>
            "bytes) and :key (a binary)"
  end

  defp check_shape!(vault, %__MODULE__{tag: tag, key: key} = struct)
       when is_binary(tag) and byte_size(tag) in 1..127 and is_binary(key) do
    if is_atom(struct.cipher) and is_atom(struct.algorithm) and is_integer(struct.iv_length) and
         struct.iv_length > 0 do
      struct
    else
      raise ArgumentError, "invalid options for #{name(vault, struct)}"
    end
  end

  defp check_shape!(vault, _struct) do
    raise ArgumentError,
          "expected each key of #{inspect(vault)} to be a map with :tag (a binary of 1 to 127 " <>
            "bytes) and :key (a binary)"
  end

  defp cloak_cipher(%{format: :cloak}), do: :aes_256_gcm
  defp cloak_cipher(%{format: :cloak_ctr}), do: :aes_256_ctr

  defp cipher_info!(vault, key, cipher) do
    :crypto.cipher_info(cipher)
  rescue
    ArgumentError ->
      reraise ArgumentError,
              [message: "unknown cipher #{inspect(cipher)} for #{name(vault, key)}"],
              __STACKTRACE__
  end

  defp name(vault, %{tag: tag}), do: "the key #{inspect(tag)} of #{inspect(vault)}"

  defimpl Inspect do
    def inspect(key, _opts) do
      "#Strongbox.Key<tag: #{Kernel.inspect(key.tag)}, format: #{Kernel.inspect(key.format)}>"
    end
  end
end
