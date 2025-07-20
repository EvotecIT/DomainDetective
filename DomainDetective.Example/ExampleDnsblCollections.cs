using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective.Example;

public static partial class Program {
    /// <summary>
    /// Demonstrates creation of DNSBL configuration with custom collections.
    /// </summary>
    public static Task ExampleDnsblCollections() {
        var config = new DnsblConfiguration {
            Providers = new DnsblEntryCollection {
                new("zen.spamhaus.org"),
                new("bl.example", enabled: false)
            },
            DomainBlockLists = new DnsblEntryCollection {
                new("dbl.example")
            },
            IpBlockLists = new BlockListEntryCollection {
                new BlockListEntry { Name = "drop", Url = "http://example.com/drop.txt" }
            }
        };

        var json = JsonSerializer.Serialize(config);
        Console.WriteLine(json);
        return Task.CompletedTask;
    }
}