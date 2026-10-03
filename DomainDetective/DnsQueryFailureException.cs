using DnsClientX;
using System;

namespace DomainDetective;

/// <summary>Retains DNS operational failure instead of treating it as absence of policy.</summary>
internal sealed class DnsQueryFailureException : Exception {
    internal DnsQueryFailureException(string name, DnsRecordType type, DnsResponse response)
        : base($"DNS query for {name} ({type}) failed: {response.Status}. {response.Error}") {
        Response = response;
    }

    internal DnsResponse Response { get; }
}
