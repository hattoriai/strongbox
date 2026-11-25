defmodule Strongbox.Index do
  @moduledoc """
  A blind index: a keyed hash of an encrypted field's value, kept beside it
  so the value can be looked up.

      field :email, Strongbox.Encrypted, vault: MyApp.Vault, redact: true
      field :email_index, Strongbox.Index, vault: MyApp.Vault, of: :email,
        normalize: [:trim, :downcase], redact: true

  The column is `:binary` in migrations, and can have a unique index.

  The index field holds the value it indexes until the record is saved,
  and its hash once saved or loaded; so pass `redact: true`, or use
  `Strongbox.Schema`. `Strongbox.Changeset.put_indexes/1` copies each
  field's value into its indexes when it changes.

  Look a value up with `Strongbox.Query.where_index/3`, which asks for its
  hash under each index key, so lookups work while index keys rotate:

      User |> Strongbox.Query.where_index(:email_index, "jose@example.com") |> Repo.one()

  `where: u.email_index == ^"jose@example.com"` works too, under the first
  index key only.

  ## Options

    * `:vault` - the vault, whose `c:Strongbox.index_keys/0` hash. Required.
    * `:of` - the field this indexes, for `Strongbox.Changeset.put_indexes/1`
      and `Strongbox.Rotation`.
    * `:as` - what the value is, as in `Strongbox.Encrypted`: `:binary`
      (the default), `:string`, `:integer`, `:date`… It is hashed as it is
      encrypted.
    * `:normalize` - what lookups may ignore, a list applied in order:
      `:trim`, `:squish` (runs of whitespace as one space), `:downcase`,
      `:upcase`, `:nfc` and `:nfkc` (Unicode normalization), `:digits`
      (only the digits: phone numbers), or `{module, function}`, called with
      the binary. Writing and querying normalize the same way. The
      encrypted field keeps the value as it was given.
    * `:context` - what this index's own key is derived from. By default
      the index field's name, so the same value gives unrelated hashes in
      two indexes. Give it to keep lookups working when the field is
      renamed.
    * `:bytes` - keep only the first bytes of each hash. Fewer bytes match
      some other values too (false positives, which the lookup's caller
      checks against the decrypted value), and so tell less about which
      rows share a value. Leave it out for unique lookups.
    * `:iterations` - hash with PBKDF2 of so many iterations instead of one
      HMAC, for values with few possibilities (phone numbers, dates of
      birth), so that guessing them is slow even with the index key.
      Each lookup and each write pays for it: 10_000 takes a few
      milliseconds.
    * `:compat` - `:ecto` or `:cloak`, to keep the hashes `Ecto.HMAC` or
      `Cloak.Ecto.HMAC` wrote, with their key as the first index key: no
      hash is computed again. See the [from Cloak](from_cloak.md) guide.

  Hashes don't hide which rows share a value, nor how often each value
  appears. Index only the fields you look up.
  """

  use Ecto.ParameterizedType

  alias Strongbox.Encoding

  @normalizers [:trim, :squish, :downcase, :upcase, :nfc, :nfkc, :digits]

  @impl true
  def init(opts) do
    field = Keyword.get(opts, :field)

    vault =
      Keyword.get(opts, :vault) ||
        raise ArgumentError, "expected a :vault for the index #{inspect(field)}"

    as = Keyword.get(opts, :as, :binary)

    unless Encoding.valid?(as) do
      raise ArgumentError, "unknown :as #{inspect(as)} for #{inspect(field)}"
    end

    %{
      vault: vault,
      of: of!(field, Keyword.get(opts, :of)),
      as: as,
      normalize: normalize!(field, Keyword.get(opts, :normalize, [])),
      context: context!(field, Keyword.get(opts, :context)),
      bytes: bytes!(field, Keyword.get(opts, :bytes)),
      iterations: iterations!(field, Keyword.get(opts, :iterations)),
      compat: compat!(field, Keyword.get(opts, :compat))
    }
  end

  @impl true
  def type(_params), do: :binary

  @impl true
  def cast(nil, _params), do: {:ok, nil}
  def cast(value, %{as: as}), do: Encoding.cast(value, as)

  @impl true
  def dump(nil, _dumper, _params), do: {:ok, nil}

  def dump(value, _dumper, params) do
    with {:ok, binary} <- prepare(value, params) do
      {:ok, Strongbox.hash(params.vault, binary, hash_opts(params))}
    end
  end

  @impl true
  def load(nil, _loader, _params), do: {:ok, nil}
  def load(value, _loader, _params) when is_binary(value), do: {:ok, value}
  def load(_value, _loader, _params), do: :error

  @impl true
  def equal?(a, b, _params), do: a == b

  @impl true
  def embed_as(_format, _params), do: :dump

  @doc """
  The hashes of `value` in the index `field` of `schema`, one under each
  index key: what a lookup asks for. Raises if `field` isn't an index.
  """
  @spec hashes(module, atom, term) :: [binary]
  def hashes(schema, field, value) do
    params = params!(schema, field)

    case cast(value, params) do
      {:ok, cast} ->
        case prepare(cast, params) do
          {:ok, binary} -> Strongbox.hashes(params.vault, binary, hash_opts(params))
          :error -> raise ArgumentError, "can't index #{inspect(value)} in #{inspect(field)}"
        end

      :error ->
        raise ArgumentError, "can't index #{inspect(value)} in #{inspect(field)}"
    end
  end

  @doc false
  # The params of an index field, or nil.
  def params(schema, field) do
    case schema.__schema__(:type, field) do
      {:parameterized, {__MODULE__, params}} -> params
      {:parameterized, __MODULE__, params} -> params
      _ -> nil
    end
  end

  @doc false
  def params!(schema, field) do
    params(schema, field) ||
      raise ArgumentError, "#{inspect(field)} of #{inspect(schema)} isn't a Strongbox.Index"
  end

  defp prepare(value, params) do
    with {:ok, binary} <- Encoding.encode(value, params.as) do
      {:ok, Enum.reduce(params.normalize, binary, &normalize/2)}
    end
  end

  defp hash_opts(params) do
    [
      context: params.context,
      bytes: params.bytes,
      iterations: params.iterations,
      compat: params.compat
    ]
  end

  defp normalize(:trim, binary), do: String.trim(binary)
  defp normalize(:squish, binary), do: binary |> String.split() |> Enum.join(" ")
  defp normalize(:downcase, binary), do: String.downcase(binary)
  defp normalize(:upcase, binary), do: String.upcase(binary)
  defp normalize(:nfc, binary), do: :unicode.characters_to_nfc_binary(binary)
  defp normalize(:nfkc, binary), do: :unicode.characters_to_nfkc_binary(binary)
  defp normalize(:digits, binary), do: for(<<c <- binary>>, c in ?0..?9, into: "", do: <<c>>)
  defp normalize({module, function}, binary), do: apply(module, function, [binary])

  defp of!(_field, nil), do: nil
  defp of!(_field, of) when is_atom(of), do: of

  defp of!(field, of),
    do:
      raise(
        ArgumentError,
        "expected :of of #{inspect(field)} to be a field name, got: #{inspect(of)}"
      )

  defp normalize!(field, list) when is_list(list) do
    Enum.each(list, fn
      n when n in @normalizers -> :ok
      {m, f} when is_atom(m) and is_atom(f) -> :ok
      other -> raise ArgumentError, "unknown normalizer #{inspect(other)} for #{inspect(field)}"
    end)

    list
  end

  defp normalize!(field, other),
    do:
      raise(
        ArgumentError,
        "expected :normalize of #{inspect(field)} to be a list, got: #{inspect(other)}"
      )

  defp context!(field, nil) when is_atom(field) and not is_nil(field), do: Atom.to_string(field)
  defp context!(_field, context) when is_binary(context) and context != "", do: context

  defp context!(field, context),
    do: raise(ArgumentError, "invalid :context #{inspect(context)} for #{inspect(field)}")

  defp bytes!(_field, nil), do: nil
  defp bytes!(_field, bytes) when is_integer(bytes) and bytes in 1..64, do: bytes

  defp bytes!(field, bytes),
    do:
      raise(
        ArgumentError,
        "expected :bytes of #{inspect(field)} from 1 to 64, got: #{inspect(bytes)}"
      )

  defp iterations!(_field, nil), do: nil
  defp iterations!(_field, n) when is_integer(n) and n > 0, do: n

  defp iterations!(field, n),
    do:
      raise(
        ArgumentError,
        "expected :iterations of #{inspect(field)} to be a positive integer, got: #{inspect(n)}"
      )

  defp compat!(_field, nil), do: nil
  defp compat!(_field, compat) when compat in [:ecto, :cloak], do: compat

  defp compat!(field, compat),
    do:
      raise(
        ArgumentError,
        "expected :compat of #{inspect(field)} to be :ecto or :cloak, got: #{inspect(compat)}"
      )
end
