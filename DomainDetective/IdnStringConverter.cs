using System;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective;

internal sealed class IdnStringConverter : JsonConverter<string>
{
    private readonly bool _unicode;
    private static readonly IdnMapping _idn = new();

    public IdnStringConverter(bool unicode)
    {
        _unicode = unicode;
    }

    public override string Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) => reader.GetString()!;

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
