using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace DomainDetective;

/// <summary>
/// Provides IP based block list functionality.
/// </summary>
public partial class DNSBLAnalysis {
    internal IpBlockListAnalysis BlockLists { get; } = new();

    /// <summary>Returns configured IP block lists.</summary>
    public IReadOnlyList<BlockListEntry> GetIpBlockLists() {
        lock (_syncRoot) {
            return BlockLists.Entries.AsReadOnly();
        }
    }

    /// <summary>Determines which lists contain the address.</summary>
    public IEnumerable<string> QueryIpBlockLists(IPAddress address) => BlockLists.ListsContaining(address);
}
