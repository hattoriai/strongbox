defmodule Strongbox.MixProject do
  use Mix.Project

  @version "0.1.0-dev"
  @source_url "https://github.com/hattoriai/strongbox"

  def project do
    [
      app: :strongbox,
      version: @version,
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
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
      # Strongbox.Rotation's tests, against PostgreSQL.
      {:ecto_sql, "~> 3.10", only: :test},
      {:postgrex, "~> 0.19", only: :test},
      {:stream_data, "~> 1.1", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
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
