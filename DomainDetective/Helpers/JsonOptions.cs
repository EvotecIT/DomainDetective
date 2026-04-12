using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace DomainDetective.Helpers;

/// <summary>Provides json options functionality.</summary>
public static class JsonOptions
{
    /// <summary>Gets the default value.</summary>
    public static JsonSerializerOptions Default { get; } = new()
    {
        WriteIndented = true,
        // Explicitly enable reflection-based metadata for environments where
        // reflection fallback is disabled by default (e.g., trimmed/AOT builds).
        TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
        Converters =
        {
            new JsonStringEnumConverter(),
            new IPAddressJsonConverter(),
            new CountryIdConverter(),
            new LocationIdConverter()
        }
    };
}
