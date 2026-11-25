defmodule Strongbox.Encoding do
  @moduledoc false
  # What an encrypted field holds (its :as), and how it becomes the binary
  # that is encrypted. The binaries are those Cloak.Ecto's types encrypt, so
  # values Cloak wrote load as they are: text for numbers and times, JSON for
  # maps and lists.

  @types [
    :binary,
    :string,
    :integer,
    :float,
    :decimal,
    :boolean,
    :date,
    :time,
    :naive_datetime,
    :utc_datetime,
    :map,
    {:array, :string},
    {:array, :integer}
  ]

  @doc false
  def types, do: @types

  @doc false
  def valid?(type), do: type in @types

  @doc false
  @spec cast(term, term) :: {:ok, term} | :error
  def cast(value, :binary) when is_binary(value), do: {:ok, value}
  def cast(_value, :binary), do: :error
  def cast(value, :map) when is_map(value) and not is_struct(value), do: {:ok, value}
  def cast(_value, :map), do: :error

  def cast(value, {:array, inner} = type) when is_list(value) do
    Ecto.Type.cast(type, value) |> only_ok(inner)
  end

  def cast(_value, {:array, _}), do: :error
  def cast(value, type), do: Ecto.Type.cast(type, value)

  defp only_ok({:ok, _} = ok, _inner), do: ok
  defp only_ok(_, _inner), do: :error

  @doc false
  @spec encode(term, term) :: {:ok, binary} | :error
  def encode(value, :binary) when is_binary(value), do: {:ok, value}

  def encode(value, :string) when is_binary(value) do
    if String.valid?(value), do: {:ok, value}, else: :error
  end

  def encode(value, :integer) when is_integer(value), do: {:ok, Integer.to_string(value)}
  def encode(value, :float) when is_float(value), do: {:ok, Float.to_string(value)}
  def encode(value, :boolean) when is_boolean(value), do: {:ok, Atom.to_string(value)}

  def encode(%Decimal{} = value, :decimal), do: {:ok, Decimal.to_string(value)}

  def encode(%Date{} = value, :date), do: {:ok, Date.to_iso8601(value)}
  def encode(%Time{} = value, :time), do: {:ok, Time.to_iso8601(value)}

  def encode(%NaiveDateTime{} = value, :naive_datetime),
    do: {:ok, NaiveDateTime.to_iso8601(value)}

  def encode(%DateTime{} = value, :utc_datetime) do
    {:ok, value |> DateTime.shift_zone!("Etc/UTC") |> DateTime.to_iso8601()}
  end

  def encode(value, :map) when is_map(value), do: Strongbox.JSON.encode(value)
  def encode(value, {:array, _}) when is_list(value), do: Strongbox.JSON.encode(value)
  def encode(_value, _type), do: :error

  @doc false
  @spec decode(binary, term) :: {:ok, term} | :error
  def decode(binary, :binary), do: {:ok, binary}

  def decode(binary, :string) do
    if String.valid?(binary), do: {:ok, binary}, else: :error
  end

  def decode(binary, :integer) do
    case Integer.parse(binary) do
      {integer, ""} -> {:ok, integer}
      _ -> :error
    end
  end

  def decode(binary, :float) do
    case Float.parse(binary) do
      {float, ""} -> {:ok, float}
      _ -> :error
    end
  end

  def decode("true", :boolean), do: {:ok, true}
  def decode("false", :boolean), do: {:ok, false}
  def decode(_binary, :boolean), do: :error

  def decode(binary, :decimal) do
    case Decimal.parse(binary) do
      {decimal, ""} -> {:ok, decimal}
      _ -> :error
    end
  end

  def decode(binary, :date), do: ok_or_error(Date.from_iso8601(binary))
  def decode(binary, :time), do: ok_or_error(Time.from_iso8601(binary))
  def decode(binary, :naive_datetime), do: ok_or_error(NaiveDateTime.from_iso8601(binary))

  def decode(binary, :utc_datetime) do
    case DateTime.from_iso8601(binary) do
      {:ok, datetime, _offset} -> {:ok, datetime}
      _ -> :error
    end
  end

  def decode(binary, :map) do
    case Strongbox.JSON.decode(binary) do
      {:ok, map} when is_map(map) -> {:ok, map}
      _ -> :error
    end
  end

  def decode(binary, {:array, inner}) do
    with {:ok, list} when is_list(list) <- Strongbox.JSON.decode(binary),
         {:ok, list} <- Ecto.Type.cast({:array, inner}, list) do
      {:ok, list}
    else
      _ -> :error
    end
  end

  defp ok_or_error({:ok, value}), do: {:ok, value}
  defp ok_or_error(_), do: :error
end

defmodule Strongbox.JSON do
  @moduledoc false
  # Elixir's JSON (1.18 and later), else Jason.

  @doc false
  def encode(value) do
    module = module!()

    try do
      {:ok, module.encode!(value)}
    rescue
      _ -> :error
    end
  end

  @doc false
  def decode(binary) do
    case module!().decode(binary) do
      {:ok, value} -> {:ok, value}
      _ -> :error
    end
  end

  defp module! do
    cond do
      Code.ensure_loaded?(JSON) -> JSON
      Code.ensure_loaded?(Jason) -> Jason
      true -> raise ArgumentError, "encrypted maps and lists need Elixir 1.18 or later, or Jason"
    end
  end
end
