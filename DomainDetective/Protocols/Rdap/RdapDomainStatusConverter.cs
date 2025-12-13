using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Converts <see cref="RdapDomainStatus"/> values to and from JSON.
/// </summary>
internal sealed class RdapDomainStatusConverter : JsonConverter<RdapDomainStatus>
{
    public override RdapDomainStatus Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (string.IsNullOrEmpty(value))
        {
            return RdapDomainStatus.Unknown;
        }
        var normalized = value!.Replace("-", string.Empty).Replace(" ", string.Empty);
        if (Enum.TryParse(normalized, true, out RdapDomainStatus status))
        {
            return status;
        }
        return RdapDomainStatus.Unknown;
    }

    public override void Write(Utf8JsonWriter writer, RdapDomainStatus value, JsonSerializerOptions options)
    {
        var name = value.ToString();
        var camel = char.ToLowerInvariant(name[0]) + name.Substring(1);
        writer.WriteStringValue(camel);
    }
}
