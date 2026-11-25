# Makes test/fixtures/cloak.json: values encrypted by Cloak itself, which
# the tests decrypt. Cloak isn't a dependency of Strongbox; to make them
# again, add {:cloak, "~> 1.1", only: :test} to mix.exs for the run, then:
#
#     MIX_ENV=test mix run test/fixtures/cloak.exs
#
# Made with Cloak 1.1.4.

key = :binary.copy(<<3>>, 32)

gcm = fn text, iv_length ->
  Cloak.Ciphers.AES.GCM.encrypt(text, key: key, tag: "AES.GCM.V1", iv_length: iv_length)
end

ctr = fn text -> Cloak.Ciphers.AES.CTR.encrypt(text, key: key, tag: "AES.CTR.V1") end

# The binaries Cloak.Ecto's types encrypt: to_string/1 of numbers and
# times (Decimal.to_string/1 of decimals), JSON of maps and lists.
texts = %{
  "binary" => "x",
  "integer" => "42",
  "float" => "1.5",
  "decimal" => "12.50",
  "date" => to_string(~D[1990-05-17]),
  "time" => to_string(~T[09:30:00]),
  "naive_datetime" => to_string(~N[2026-11-25 10:00:00]),
  "utc_datetime" => to_string(~U[2026-11-25 10:00:00Z]),
  "map" => ~s({"a":1}),
  "integer_list" => "[1,2]",
  "email" => "ana@example.com"
}

values =
  for {name, text} <- texts, into: %{} do
    {:ok, ciphertext} = gcm.(text, 16)
    {name, %{"text" => text, "ciphertext" => Base.encode16(ciphertext)}}
  end

{:ok, gcm12} = gcm.("from cloak", 12)
{:ok, gcm16} = gcm.("from cloak", 16)
{:ok, ctr} = ctr.("from cloak ctr")

File.write!(
  Path.join(__DIR__, "cloak.json"),
  JSON.encode!(%{
    "made_with" => "cloak #{Application.spec(:cloak, :vsn)}",
    "key" => Base.encode16(key),
    "gcm_iv16" => Base.encode16(gcm16),
    "gcm_iv12" => Base.encode16(gcm12),
    "ctr" => Base.encode16(ctr),
    "values" => values
  })
)
