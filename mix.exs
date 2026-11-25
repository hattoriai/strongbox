defmodule Strongbox.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/hattoriai/strongbox"

  def project do
    [
      app: :strongbox,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      # test/fixtures/cloak.exs makes a fixture; it is not a test.
      test_ignore_filters: [&String.starts_with?(&1, "test/fixtures/")],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      dialyzer: [
        plt_add_apps: [:mix, :ex_unit],
        plt_core_path: "priv/plts",
        plt_file: {:no_warn, "priv/plts/project.plt"}
      ],
      package: package(),
      docs: docs(),
      description: description(),
      name: "Strongbox",
      source_url: @source_url,
      homepage_url: @source_url
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Ecto 3.10 and later: parameterized types with their field's name.
      {:ecto, "~> 3.10"},
      # Encrypted maps and lists as JSON with Jason, beside Elixir's own JSON
      # (1.18 and later). Optional.
      {:jason, "~> 1.4", optional: true},
      # Strongbox.Rotation's tests, against PostgreSQL and SQLite.
      {:ecto_sql, "~> 3.10", only: :test},
      {:postgrex, "~> 0.19", only: :test},
      {:ecto_sqlite3, "~> 0.22", only: :test},
      {:stream_data, "~> 1.1", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp aliases do
    [
      # On an up-to-date main, after the release pull request: check the
      # repository, publish to Hex, then tag the version. The check runs in
      # a child VM: once anything compiles in this VM, Mix no longer finds
      # the tasks of the Hex archive.
      release: [
        "cmd mix strongbox.release_check",
        "hex.publish --yes",
        "cmd git tag v#{@version}",
        "cmd git push origin v#{@version}"
      ]
    ]
  end

  defp description do
    "Encrypted fields for Ecto: values bound to their field, blind indexes to find them, " <>
      "and keys you can rotate."
  end

  defp package do
    [
      name: "strongbox",
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs .formatter.exs guides README.md CHANGELOG.md LICENSE NOTICE)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url,
      assets: %{"media" => "media"},
      extras: [
        "README.md",
        "guides/keys.md",
        "guides/blind_indexes.md",
        "guides/rotation.md",
        "guides/from_cloak.md",
        "guides/format.md",
        "CHANGELOG.md"
      ],
      groups_for_modules: [
        Vault: [Strongbox, Strongbox.Key, Strongbox.DecryptionError],
        Ecto: [Strongbox.Encrypted, Strongbox.Index, Strongbox.Schema, Strongbox.Changeset],
        Lookups: [Strongbox.Query],
        Rotation: [Strongbox.Rotation]
      ]
    ]
  end
end
