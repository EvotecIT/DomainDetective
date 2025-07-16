namespace DomainDetective
{
using System.Text.Json;

/// <summary>
/// Provides JSON serializer options for RDAP objects.
/// </summary>
public static class RdapJson
{
    /// <summary>Default serializer options.</summary>
    public static readonly JsonSerializerOptions Options;

    static RdapJson()
    {
        Options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        Options.Converters.Add(new RdapStatusConverter());
        Options.Converters.Add(new RdapEventActionConverter());
    }
}
}
