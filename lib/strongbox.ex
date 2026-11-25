defmodule Strongbox do
  @moduledoc """
  Encrypted fields for Ecto.

  A vault is a module of your app that holds the keys:

      defmodule MyApp.Vault do
        use Strongbox

        @impl true
        def keys do
          [%{tag: "k1", key: Application.fetch_env!(:my_app, :strongbox_key_k1)}]
        end

        @impl true
        def index_keys do
          [%{tag: "i1", key: Application.fetch_env!(:my_app, :strongbox_index_key_i1)}]
        end
      end

  Then a schema names it for its encrypted fields:

      schema "users" do
        field :ssn, Strongbox.Encrypted, vault: MyApp.Vault, redact: true
        field :email, Strongbox.Encrypted, vault: MyApp.Vault, redact: true
        field :email_index, Strongbox.Index, vault: MyApp.Vault, of: :email, normalize: [:trim, :downcase]
      end

  or, with `Strongbox.Schema`, which never forgets `redact: true`:

      use Strongbox.Schema, vault: MyApp.Vault

      schema "users" do
        encrypted_field :ssn
        encrypted_field :email
        blind_index :email_index, of: :email, normalize: [:trim, :downcase]
      end

  A vault isn't a process: it starts nothing and holds no state. Its
  callbacks are called for every value, so they must be cheap: read keys
  that `config/runtime.exs` decoded once, never decode them in the callback.

  ## The vault's functions

  `use Strongbox` defines, in the vault:

    * `encrypt(plaintext, opts)` and `decrypt(ciphertext, opts)` (and
      `decrypt!/2`), for binaries outside Ecto. Options: `:context`, a
      binary the value is bound to, which decrypting must give again; and
      `:pad`, a block size the value is padded to.
    * `hash(value, opts)`, a blind index of a binary with the first index
      key, and `hashes(value, opts)`, one with each index key, for lookups
      while index keys rotate. Options as `Strongbox.Index`'s:
      `:context`, `:bytes`, `:iterations` and `:compat`.
    * `stale?(ciphertext)`, whether a value was written with a key, or in a
      format, other than the first key's, so rotating would write it again.
  """

  alias Strongbox.{Cipher, Hash, Key}

  @doc """
  The keys that encrypt and decrypt. The first encrypts, all decrypt.

  Each is a map (or a `Strongbox.Key`) with `:tag` and `:key`, and
  optionally `:cipher` and `:format`. See `Strongbox.Key`.
  """
  @callback keys() :: [Key.t() | map, ...]

  @doc """
  The keys of blind indexes. The first writes, all are looked up.

  Each is a map (or a `Strongbox.Key`) with `:tag` and `:key`, and
  optionally `:algorithm`. Never one of `c:keys/0`. Only needed for
  `Strongbox.Index`.
  """
  @callback index_keys() :: [Key.t() | map, ...]

  @optional_callbacks index_keys: 0

  @doc false
  defmacro __using__(_opts) do
    quote location: :keep do
      @behaviour Strongbox

      @doc "Encrypts a binary with the first key. See `Strongbox`."
      def encrypt(plaintext, opts \\ []), do: Strongbox.encrypt(__MODULE__, plaintext, opts)

      @doc "Decrypts a binary. See `Strongbox`."
      def decrypt(ciphertext, opts \\ []), do: Strongbox.decrypt(__MODULE__, ciphertext, opts)

      @doc "Decrypts a binary, or raises `Strongbox.DecryptionError`."
      def decrypt!(ciphertext, opts \\ []), do: Strongbox.decrypt!(__MODULE__, ciphertext, opts)

      @doc "The blind index of a binary, with the first index key."
      def hash(value, opts \\ []), do: Strongbox.hash(__MODULE__, value, opts)

      @doc "The blind indexes of a binary, one with each index key."
      def hashes(value, opts \\ []), do: Strongbox.hashes(__MODULE__, value, opts)

      @doc "Whether rotating would write the value again."
      def stale?(ciphertext), do: Strongbox.stale?(__MODULE__, ciphertext)
    end
  end

  @doc """
  Encrypts `plaintext` with the first key of `vault`.
  """
  @spec encrypt(module, binary, keyword) :: binary
  def encrypt(vault, plaintext, opts \\ [])

  def encrypt(vault, plaintext, opts) when is_atom(vault) and is_binary(plaintext) do
    vault |> keys!() |> Cipher.encrypt(plaintext, cipher_opts(opts))
  end

  def encrypt(_vault, _plaintext, _opts), do: raise(ArgumentError, "expected a binary to encrypt")

  @doc """
  Decrypts `ciphertext` with the key of `vault` it names.

  Returns `:error` when no key has its tag, when it was changed, or when
  the `:context` isn't the one it was encrypted with.
  """
  @spec decrypt(module, binary, keyword) :: {:ok, binary} | :error
  def decrypt(vault, ciphertext, opts \\ [])

  def decrypt(vault, ciphertext, opts) when is_atom(vault) and is_binary(ciphertext) do
    vault |> keys!() |> Cipher.decrypt(ciphertext, cipher_opts(opts))
  end

  def decrypt(_vault, _ciphertext, _opts),
    do: raise(ArgumentError, "expected a binary to decrypt")

  @doc """
  Decrypts `ciphertext`, or raises `Strongbox.DecryptionError`.
  """
  @spec decrypt!(module, binary, keyword) :: binary
  def decrypt!(vault, ciphertext, opts \\ []) do
    case decrypt(vault, ciphertext, opts) do
      {:ok, plaintext} -> plaintext
      :error -> raise Strongbox.DecryptionError, vault: vault, ciphertext: ciphertext
    end
  end

  @doc """
  The blind index of `value` with the first index key of `vault`.
  """
  @spec hash(module, binary, keyword) :: binary
  def hash(vault, value, opts \\ []) when is_atom(vault) and is_binary(value) do
    [key | _] = index_keys!(vault)
    Hash.hash(key, value, opts)
  end

  @doc """
  The blind indexes of `value`, one with each index key of `vault`, without
  repeats: what a lookup asks for while index keys rotate.
  """
  @spec hashes(module, binary, keyword) :: [binary, ...]
  def hashes(vault, value, opts \\ []) when is_atom(vault) and is_binary(value) do
    vault |> index_keys!() |> Enum.map(&Hash.hash(&1, value, opts)) |> Enum.uniq()
  end

  @doc """
  Whether `ciphertext` was written with a key or in a format other than
  the first key's, so that rotating would write it again.
  """
  @spec stale?(module, binary) :: boolean
  def stale?(vault, ciphertext) when is_atom(vault) and is_binary(ciphertext) do
    [current | _] = keys!(vault)
    version = if current.format == :ecto, do: 1, else: 2

    case Cipher.describe(ciphertext) do
      {:ok, %{version: ^version, tag: tag}} -> tag != current.tag
      _ -> true
    end
  end

  @doc false
  @spec keys!(module) :: [Key.t(), ...]
  def keys!(vault), do: Key.encryption_keys!(vault, vault.keys())

  @doc false
  @spec index_keys!(module) :: [Key.t(), ...]
  def index_keys!(vault) do
    if Code.ensure_loaded?(vault) and function_exported?(vault, :index_keys, 0) do
      Key.index_keys!(vault, vault.index_keys())
    else
      raise ArgumentError, "#{inspect(vault)} has no index_keys/0, which blind indexes need"
    end
  end

  defp cipher_opts(opts) do
    context = Keyword.get(opts, :context, "")

    unless is_binary(context) do
      raise ArgumentError, "expected :context to be a binary, got: #{inspect(context)}"
    end

    pad = Keyword.get(opts, :pad)

    unless is_nil(pad) or (is_integer(pad) and pad in 1..65_536) do
      raise ArgumentError,
            "expected :pad to be a block size from 1 to 65536, got: #{inspect(pad)}"
    end

    [context: context, pad: pad]
  end
end

defmodule Strongbox.DecryptionError do
  @moduledoc """
  Raised when a value can't be decrypted: no key has its tag, it was
  changed, or it belongs to another field.

  The message names the vault and the value's tag, never the value.
  """
  defexception [:message]

  @impl true
  def exception(opts) do
    vault = Keyword.fetch!(opts, :vault)

    tag =
      case Strongbox.Cipher.describe(Keyword.get(opts, :ciphertext, "")) do
        {:ok, %{tag: tag}} -> " (tag #{inspect(tag)})"
        :error -> ""
      end

    %__MODULE__{
      message:
        "could not decrypt a value#{tag} with #{inspect(vault)}: no key has its tag, " <>
          "it was changed, or it belongs to another field"
    }
  end
end
