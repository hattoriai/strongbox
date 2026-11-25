defmodule Strongbox.CloakFixtures do
  @moduledoc false
  # Values Cloak 1.1.4 encrypted, from test/fixtures/cloak.json (made by
  # test/fixtures/cloak.exs), so the tests read Cloak's own bytes without
  # Cloak as a dependency.

  @path Path.expand("../fixtures/cloak.json", __DIR__)
  @external_resource @path

  def key, do: Base.decode16!(data()["key"])

  # "from cloak", AES.GCM under "AES.GCM.V1", with IVs of 16 or 12 bytes.
  def gcm(16), do: Base.decode16!(data()["gcm_iv16"])
  def gcm(12), do: Base.decode16!(data()["gcm_iv12"])

  # "from cloak ctr", AES.CTR under "AES.CTR.V1".
  def ctr, do: Base.decode16!(data()["ctr"])

  # A value of a Cloak.Ecto type, AES.GCM under "AES.GCM.V1": its text and
  # the ciphertext.
  def value(name) do
    %{"text" => text, "ciphertext" => ciphertext} = Map.fetch!(data()["values"], name)
    {text, Base.decode16!(ciphertext)}
  end

  defp data do
    {:ok, data} = @path |> File.read!() |> Strongbox.JSON.decode()
    data
  end
end
