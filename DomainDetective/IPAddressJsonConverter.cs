using System;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Converts <see cref="IPAddress"/> values to and from JSON.
/// </summary>
internal sealed class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    /// <summary>
    /// Reads an <see cref="IPAddress"/> from the JSON reader.
    /// </summary>
    /// <param name="reader">The JSON reader instance.</param>
    /// <param name="typeToConvert">The type to convert.</param>
    /// <param name="options">Serialization options.</param>
    /// <returns>The parsed <see cref="IPAddress"/>.</returns>
    /// <exception cref="FormatException">Value is not a valid IP address.</exception>
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

    /// <summary>
    /// Writes the specified <see cref="IPAddress"/> to the JSON writer.
    /// </summary>
    /// <param name="writer">The JSON writer to use.</param>
    /// <param name="value">The IP address value.</param>
    /// <param name="options">Serialization options.</param>
    public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}
