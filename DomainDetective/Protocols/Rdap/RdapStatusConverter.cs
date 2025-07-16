using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective
{
/// <summary>
/// Converts <see cref="RdapStatus"/> values to and from JSON.
/// </summary>
internal sealed class RdapStatusConverter : JsonConverter<RdapStatus>
{
    public override RdapStatus Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (string.IsNullOrEmpty(value))
        {
            return RdapStatus.Unknown;
        }
        var normalized = value.Replace("-", string.Empty).Replace(" ", string.Empty);
        if (Enum.TryParse(normalized, true, out RdapStatus status))
        {
            return status;
        }
        return RdapStatus.Unknown;
    }

    public override void Write(Utf8JsonWriter writer, RdapStatus value, JsonSerializerOptions options)
    {
        var name = value.ToString();
        var camel = char.ToLowerInvariant(name[0]) + name.Substring(1);
        writer.WriteStringValue(camel);
    }
}
}
