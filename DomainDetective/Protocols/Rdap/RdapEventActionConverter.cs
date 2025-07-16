using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DomainDetective
{
/// <summary>
/// Converts <see cref="RdapEventAction"/> values to and from JSON.
/// </summary>
internal sealed class RdapEventActionConverter : JsonConverter<RdapEventAction>
{
    public override RdapEventAction Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var value = reader.GetString();
        if (string.IsNullOrEmpty(value))
        {
            return RdapEventAction.Unknown;
        }
        var normalized = value.Replace("-", string.Empty).Replace(" ", string.Empty);
        if (Enum.TryParse(normalized, true, out RdapEventAction action))
        {
            return action;
        }
        return RdapEventAction.Unknown;
    }

    public override void Write(Utf8JsonWriter writer, RdapEventAction value, JsonSerializerOptions options)
    {
        var name = value.ToString();
        var camel = char.ToLowerInvariant(name[0]) + name.Substring(1);
        writer.WriteStringValue(camel);
    }
}
}
