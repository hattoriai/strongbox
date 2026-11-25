defmodule Strongbox.Encrypted do
  @moduledoc """
  An encrypted field.

      field :ssn, Strongbox.Encrypted, vault: MyApp.Vault, redact: true
      field :notes, Strongbox.Encrypted, vault: MyApp.Vault, as: :map, redact: true
      field :born_on, Strongbox.Encrypted, vault: MyApp.Vault, as: :date, redact: true

  The column is `:binary` in migrations (`bytea` in PostgreSQL), or
  `:text` with `encoding: :base64`.

  Pass `redact: true`, or use `Strongbox.Schema`, which always does: else
  the decrypted value shows when the struct is inspected, in logs and in
  error reports.

  ## Options

    * `:vault` - the vault, a module that uses `Strongbox`. Required.
    * `:as` - what the field holds: `:binary` (the default, any binary),
      `:string` (valid UTF-8), `:integer`, `:float`, `:decimal`, `:boolean`,
      `:date`, `:time`, `:naive_datetime`, `:utc_datetime`, `:map`,
      `{:array, :string}` or `{:array, :integer}`. Maps and lists are kept
      as JSON, so a map's keys load as strings, as with Ecto's `:map`.
    * `:context` - the binary each value is bound to. By default, the
      field's name: a value copied into another field (`ssn` into `notes`)
      no longer decrypts there. Give it to keep values readable when the
      field is renamed: `context: "ssn"`. `false` binds values to nothing,
      as `Ecto.Encrypted` and Cloak do.
    * `:pad` - a block size, such as `16` or `64`: each value is padded to
      a multiple of it before it is encrypted, so its length shows only to
      the block. Use it for fields with few values (`"yes"`, `"no"`) or
      whose length tells something.
    * `:encoding` - `:raw` (the default) keeps the encrypted bytes as they
      are, in a binary column. `:base64` keeps them as text: for a `:text`
      column, and for fields of embedded schemas kept as JSON.

  ## Querying

  Each value is encrypted with a random salt, so the same value never
  encrypts twice the same way, and `where: u.ssn == ^ssn` matches nothing.
  To look a value up, keep a blind index of it beside it:
  `Strongbox.Index`.
  """

  use Ecto.ParameterizedType

  alias Strongbox.Encoding

  @impl true
  def init(opts) do
    field = Keyword.get(opts, :field)
    vault = Keyword.get(opts, :vault) || raise ArgumentError, missing_vault(field)

    unless is_atom(vault) do
      raise ArgumentError,
            "expected :vault of #{inspect(field)} to be a module, got: #{inspect(vault)}"
    end

    as = Keyword.get(opts, :as, :binary)

    unless Encoding.valid?(as) do
      raise ArgumentError,
            "unknown :as #{inspect(as)} for #{inspect(field)}, expected one of " <>
              inspect(Encoding.types())
    end

    %{
      vault: vault,
      as: as,
      context: context!(field, Keyword.get(opts, :context)),
      pad: pad!(field, Keyword.get(opts, :pad)),
      encoding: encoding!(field, Keyword.get(opts, :encoding, :raw))
    }
  end

  @impl true
  def type(%{encoding: :base64}), do: :string
  def type(_params), do: :binary

  @impl true
  def cast(nil, _params), do: {:ok, nil}
  def cast(value, %{as: as}), do: Encoding.cast(value, as)

  @impl true
  def dump(nil, _dumper, _params), do: {:ok, nil}

  def dump(value, _dumper, params) do
    with {:ok, binary} <- Encoding.encode(value, params.as) do
      ciphertext =
        Strongbox.encrypt(params.vault, binary, context: params.context, pad: params.pad)

      {:ok, encode(ciphertext, params.encoding)}
    end
  end

  @impl true
  def load(nil, _loader, _params), do: {:ok, nil}

  def load(value, _loader, params) when is_binary(value) do
    with {:ok, ciphertext} <- decode(value, params.encoding),
         {:ok, binary} <- Strongbox.decrypt(params.vault, ciphertext, context: params.context) do
      Encoding.decode(binary, params.as)
    end
  end

  def load(_value, _loader, _params), do: :error

  @impl true
  def equal?(a, b, _params), do: a == b

  # Never put a decrypted value in an embed.
  @impl true
  def embed_as(_format, _params), do: :dump

  @doc false
  # The stored value as encrypted bytes, for rotation.
  def ciphertext(value, %{encoding: encoding}), do: decode(value, encoding)

  defp encode(ciphertext, :raw), do: ciphertext
  defp encode(ciphertext, :base64), do: Base.encode64(ciphertext)

  defp decode(value, :raw), do: {:ok, value}
  defp decode(value, :base64), do: Base.decode64(value)

  defp context!(field, nil) when is_atom(field) and not is_nil(field), do: Atom.to_string(field)
  defp context!(field, nil), do: raise(ArgumentError, "expected a :context for #{inspect(field)}")
  defp context!(_field, false), do: ""
  defp context!(_field, context) when is_binary(context) and context != "", do: context

  defp context!(field, context) do
    raise ArgumentError,
          "expected :context of #{inspect(field)} to be a non-empty binary or false, " <>
            "got: #{inspect(context)}"
  end

  defp pad!(_field, nil), do: nil
  defp pad!(_field, pad) when is_integer(pad) and pad in 1..65_536, do: pad

  defp pad!(field, pad) do
    raise ArgumentError,
          "expected :pad of #{inspect(field)} to be a block size from 1 to 65536, got: #{inspect(pad)}"
  end

  defp encoding!(_field, encoding) when encoding in [:raw, :base64], do: encoding

  defp encoding!(field, encoding) do
    raise ArgumentError,
          "expected :encoding of #{inspect(field)} to be :raw or :base64, got: #{inspect(encoding)}"
  end

  defp missing_vault(field), do: "expected a :vault for the encrypted field #{inspect(field)}"
end
