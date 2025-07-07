using System;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Handles IDN encoding and decoding when serializing strings.
/// </summary>
internal sealed class IdnStringConverter : JsonConverter<string>
{
    private readonly bool _unicode;
    private static readonly IdnMapping _idn = new();

    /// <summary>
    /// Initializes a new instance indicating whether unicode output is desired.
    /// </summary>
    /// <param name="unicode">True to convert to Unicode when writing.</param>
    public IdnStringConverter(bool unicode)
    {
        _unicode = unicode;
    }

    /// <inheritdoc/>
    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.GetString()!;

    /// <inheritdoc/>
    public override void Write(Utf8JsonWriter writer, string value, JsonSerializerOptions options)
    {
        if (_unicode && !string.IsNullOrEmpty(value))
        {
            try
            {
                value = _idn.GetUnicode(value);
            }
            catch (ArgumentException)
            {
                // ignore invalid IDN strings
            }
        }

        writer.WriteStringValue(value);
    }
}
