using System;
using System.Collections.Generic;
namespace DomainDetective {
    /// <summary>
    /// Result of a DNS propagation query for a single server.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsPropagationResult {
        /// <summary>Gets the server that was queried.</summary>
        public PublicDnsEntry Server { get; init; }
        /// <summary>Gets the records returned by the server.</summary>
        public IEnumerable<string> Records { get; init; }
        /// <summary>Gets the time the query took.</summary>
        public TimeSpan Duration { get; init; }
        /// <summary>Gets a value indicating whether the query succeeded.</summary>
        public bool Success { get; init; }
        /// <summary>Gets an error message if the query failed.</summary>
        public string Error { get; init; }
    }
}
