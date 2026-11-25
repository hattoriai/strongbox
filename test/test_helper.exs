Strongbox.TestVault.reset()

# PostgreSQL, for the tests of lookups and rotation (tagged :db). They are
# left out when it can't be reached.
url = System.get_env("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/strongbox_test")

Application.put_env(:strongbox, Strongbox.TestRepo,
  url: url,
  pool: Ecto.Adapters.SQL.Sandbox,
  log: false
)

db? =
  case Ecto.Adapters.Postgres.storage_up(Strongbox.TestRepo.config()) do
    result when result in [:ok, {:error, :already_up}] ->
      {:ok, _} = Strongbox.TestRepo.start_link()

      Ecto.Adapters.SQL.query!(Strongbox.TestRepo, "DROP TABLE IF EXISTS users")

      Ecto.Adapters.SQL.query!(Strongbox.TestRepo, """
      CREATE TABLE users (
        id uuid PRIMARY KEY,
        name text,
        email bytea,
        ssn bytea,
        born_on bytea,
        notes bytea,
        email_index bytea,
        ssn_index bytea
      )
      """)

      Ecto.Adapters.SQL.query!(
        Strongbox.TestRepo,
        "CREATE UNIQUE INDEX users_email_index_index ON users (email_index)"
      )

      Ecto.Adapters.SQL.Sandbox.mode(Strongbox.TestRepo, :manual)
      true

    {:error, reason} ->
      IO.puts("PostgreSQL unavailable, leaving out the :db tests (#{inspect(reason)})")
      false
  end

# SQLite, in memory, for the same: it keeps an encrypted value as a BLOB,
# which is never equal to a text.
Application.put_env(:strongbox, Strongbox.TestSQLiteRepo,
  database: ":memory:",
  pool_size: 1,
  log: false
)

{:ok, _} = Strongbox.TestSQLiteRepo.start_link()

Ecto.Adapters.SQL.query!(Strongbox.TestSQLiteRepo, """
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  name TEXT,
  email BLOB,
  ssn BLOB,
  born_on BLOB,
  notes BLOB,
  email_index BLOB,
  ssn_index BLOB
)
""")

ExUnit.start(exclude: if(db?, do: [], else: [:db]))
