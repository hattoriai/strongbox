defmodule Strongbox.Hash do
  @moduledoc false
  # Blind indexes. The [blind indexes](blind_indexes.md) guide explains the
  # choices; the [format](format.md) guide gives each computation.
  #
  # Strongbox's own: each index has a key of its own, derived from the index
  # key and the index's context, so the same value gives unrelated hashes in
  # two indexes:
  #
  #   index_key = HMAC(algorithm, key, "Strongbox.Index " <> context)
  #   hash      = HMAC(algorithm, index_key, value)
  #             or PBKDF2-HMAC(algorithm, value, index_key, iterations), with :iterations
  #
  # cut to :bytes when given. With compat: :ecto, Ecto.HMAC's hash,
  # HMAC(algorithm, key, "Ecto.HMAC" <> value); with compat: :cloak,
  # Cloak.Ecto.HMAC's, HMAC(algorithm, key, value).

  alias Strongbox.Key

  @spec hash(Key.t(), binary, keyword) :: binary
  def hash(%Key{} = key, value, opts) when is_binary(value) do
    size = :crypto.hash_info(key.algorithm).size

    hash =
      case Keyword.get(opts, :compat) do
        nil -> own(key, value, size, opts)
        :ecto -> :crypto.mac(:hmac, key.algorithm, key.key, ["Ecto.HMAC", value])
        :cloak -> :crypto.mac(:hmac, key.algorithm, key.key, value)
      end

    case Keyword.get(opts, :bytes) do
      nil -> hash
      bytes -> binary_part(hash, 0, min(bytes, byte_size(hash)))
    end
  rescue
    e -> reraise e, prune(__STACKTRACE__)
  end

  defp own(key, value, size, opts) do
    context = Keyword.get(opts, :context, "")
    index_key = :crypto.mac(:hmac, key.algorithm, key.key, ["Strongbox.Index ", context])

    case Keyword.get(opts, :iterations) do
      nil -> :crypto.mac(:hmac, key.algorithm, index_key, value)
      iterations -> :crypto.pbkdf2_hmac(key.algorithm, value, index_key, iterations, size)
    end
  end

  defp prune([{mod, fun, [_ | _] = args, info} | rest]),
    do: [{mod, fun, length(args), info} | rest]

  defp prune(stacktrace), do: stacktrace
end
