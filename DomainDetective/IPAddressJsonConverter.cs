using System;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective;

internal sealed class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    public override IPAddress Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (!IPAddress.TryParse(value, out var ip))
        {
            var index = reader.TokenStartIndex;
            throw new FormatException($"Invalid IP address '{value}' at index {index}");
        }
        return ip;
    }

    public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}
