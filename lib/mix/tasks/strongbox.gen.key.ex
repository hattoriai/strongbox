defmodule Mix.Tasks.Strongbox.Gen.Key do
  @shortdoc "Prints a new random key in Base64"

  @moduledoc """
  Prints a new random key in Base64, for a vault's `keys/0` or
  `index_keys/0`.

      $ mix strongbox.gen.key
      $ mix strongbox.gen.key --bytes 16

  32 bytes by default: what AES-256-GCM and ChaCha20-Poly1305 take, and
  enough for an index key under SHA-256. Use 64 for an index key under
  SHA-512, 16 for AES-128-GCM.

  Keep it in an environment variable, never in the code or the
  repository, and decode it in `config/runtime.exs`:

      config :my_app, :strongbox_key_k1, Strongbox.Key.decode!(System.fetch_env!("STRONGBOX_KEY_K1"))
  """

  use Mix.Task

  @impl true
  def run(args) do
    {opts, _rest} = OptionParser.parse!(args, strict: [bytes: :integer])
    bytes = Keyword.get(opts, :bytes, 32)

    unless bytes in 16..128 do
      Mix.raise("--bytes must be from 16 to 128")
    end

    Mix.shell().info(Base.encode64(Strongbox.Key.generate(bytes)))
  end
end
