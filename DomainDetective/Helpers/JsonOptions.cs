using System;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace DomainDetective.Helpers;

/// <summary>Provides JSON options for scan results and reporting artifacts.</summary>
public static class JsonOptions
{
    /// <summary>Gets options that project certificates and failures and omit runtime services and callbacks.</summary>
    public static JsonSerializerOptions Default { get; } = CreateDefault();

    private static JsonSerializerOptions CreateDefault() {
        // Explicitly enable reflection-based metadata for environments where
        // reflection fallback is disabled by default (e.g., trimmed/AOT builds).
        var resolver = new DefaultJsonTypeInfoResolver();
        resolver.Modifiers.Add(info => {
            // These are execution dependencies, not scan evidence. Traversing a client can
            // expose credentials in its headers; delegates are unsupported by System.Text.Json.
            for (var i = info.Properties.Count - 1; i >= 0; i--) {
                var type = info.Properties[i].PropertyType;
                if (typeof(Delegate).IsAssignableFrom(type) ||
                    typeof(HttpClient).IsAssignableFrom(type) ||
                    typeof(IHttpClientFactory).IsAssignableFrom(type)) {
                    info.Properties.RemoveAt(i);
                }
            }
        });
        return new JsonSerializerOptions {
            WriteIndented = true,
            TypeInfoResolver = resolver,
            Converters = {
                new JsonStringEnumConverter(),
                new IPAddressJsonConverter(),
                new CountryIdConverter(),
                new LocationIdConverter(),
                new X509CertificateJsonConverter(),
                new ExceptionJsonConverter()
            }
        };
    }
}
