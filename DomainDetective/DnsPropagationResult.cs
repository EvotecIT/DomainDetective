using DnsClientX;
using System;
using System.Collections.Generic;
namespace DomainDetective {
    /// <summary>
    /// Result of a DNS propagation query for a single server.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Each result captures the raw answers returned by the resolver along
    /// with metadata about query success and duration.
    /// </remarks>
    public class DnsPropagationResult {
        /// <summary>Gets the server that was queried.</summary>
        public PublicDnsEntry Server { get; init; } = null!;
        /// <summary>Gets the DNS record type that was queried.</summary>
        public DnsRecordType RecordType { get; init; }
        /// <summary>Gets the records returned by the server.</summary>
        public IEnumerable<string> Records { get; init; } = Array.Empty<string>();
        /// <summary>Gets the time the query took.</summary>
        public TimeSpan Duration { get; init; }
        /// <summary>Gets a value indicating whether the query succeeded.</summary>
        public bool Success { get; init; }
        /// <summary>Gets an error message if the query failed.</summary>
        public string Error { get; init; } = string.Empty;

        /// <summary>Gets geolocation information for returned IP addresses.</summary>
        public IReadOnlyDictionary<string, GeoLocationInfo>? Geo { get; init; }
    }
}
