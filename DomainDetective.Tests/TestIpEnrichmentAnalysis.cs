using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestIpEnrichmentAnalysis
{
    [Fact]
    public async Task EnrichesApexMxNsAndCustomIps()
    {
        using var vcardA = JsonDocument.Parse("[\"vcard\", [[\"fn\", {}, \"text\", \"Example ASN A\"]]]");
        using var vcardB = JsonDocument.Parse("[\"vcard\", [[\"fn\", {}, \"text\", \"Example ASN B\"]]]");

        var analysis = new IpEnrichmentAnalysis
        {
            IncludeMxHostAddresses = true,
            IncludeNsHostAddresses = true,
            MaxHostsPerKind = 10,
            MaxUniqueIpsToEnrich = 50,
            QueryOverride = (name, type, _) =>
            {
                name = (name ?? string.Empty).Trim().TrimEnd('.');

                if (name.Equals("example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.A)
                {
                    return Task.FromResult(new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.A, TTL = 300, DataRaw = "192.0.2.1" }
                    });
                }
                if (name.Equals("example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.MX)
                {
                    return Task.FromResult(new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.MX, TTL = 300, DataRaw = "10 mx.example.net." }
                    });
                }
                if (name.Equals("example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.NS)
                {
                    return Task.FromResult(new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.NS, TTL = 300, DataRaw = "ns1.example.net." }
                    });
                }
                if (name.Equals("mx.example.net", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.A)
                {
                    return Task.FromResult(new[]
                    {
                        new DnsAnswer { Name = "mx.example.net", Type = DnsRecordType.A, TTL = 60, DataRaw = "198.51.100.10" }
                    });
                }
                if (name.Equals("ns1.example.net", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.A)
                {
                    return Task.FromResult(new[]
                    {
                        new DnsAnswer { Name = "ns1.example.net", Type = DnsRecordType.A, TTL = 60, DataRaw = "203.0.113.53" }
                    });
                }

                if (type == DnsRecordType.PTR && name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(new[]
                    {
                        new DnsAnswer { Name = name, Type = DnsRecordType.PTR, TTL = 3600, DataRaw = "ptr.example.net." }
                    });
                }

                return Task.FromResult(Array.Empty<DnsAnswer>());
            },
            RdapQueryOverride = (ip, _) =>
            {
                if (ip == "192.0.2.1")
                {
                    return Task.FromResult<RdapIpNetwork?>(new RdapIpNetwork
                    {
                        Country = "US",
                        Cidr = "192.0.2.0/24",
                        Entities = new[] { new RdapEntity { Handle = "AS64500", VcardArray = vcardA.RootElement } }
                    });
                }

                if (ip == "198.51.100.10")
                {
                    return Task.FromResult<RdapIpNetwork?>(new RdapIpNetwork
                    {
                        Country = "US",
                        Cidr = "198.51.100.0/24",
                        Entities = new[] { new RdapEntity { Handle = "AS64501", VcardArray = vcardB.RootElement } }
                    });
                }

                if (ip == "203.0.113.53")
                {
                    return Task.FromResult<RdapIpNetwork?>(new RdapIpNetwork
                    {
                        Country = "PL",
                        Cidr = "203.0.113.0/24",
                        Entities = Array.Empty<RdapEntity>()
                    });
                }

                if (ip == "203.0.113.99")
                {
                    return Task.FromResult<RdapIpNetwork?>(new RdapIpNetwork
                    {
                        Country = "PL",
                        Cidr = "203.0.113.0/24",
                        Entities = new[] { new RdapEntity { Handle = "AS64502" } }
                    });
                }

                return Task.FromResult<RdapIpNetwork?>(null);
            }
        };

        var logger = new InternalLogger();
        await analysis.AnalyzeAsync("example.com", additionalIpAddresses: new[] { "203.0.113.99" }, logger: logger, cancellationToken: CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.False(analysis.ResultsCapped);
        Assert.Equal(4, analysis.UniqueIpCount);
        Assert.Equal(4, analysis.RowCount);
        Assert.Equal(3, analysis.DistinctAsnCount); // 64500, 64501, 64502
        Assert.Equal(2, analysis.DistinctCountryCount); // US, PL

        Assert.Contains(analysis.Rows, r => r.SourceKind == IpEnrichmentSourceKind.Apex && r.IpAddress == "192.0.2.1");
        Assert.Contains(analysis.Rows, r => r.SourceKind == IpEnrichmentSourceKind.Mx && r.IpAddress == "198.51.100.10");
        Assert.Contains(analysis.Rows, r => r.SourceKind == IpEnrichmentSourceKind.Ns && r.IpAddress == "203.0.113.53");
        Assert.Contains(analysis.Rows, r => r.SourceKind == IpEnrichmentSourceKind.Custom && r.IpAddress == "203.0.113.99");

        Assert.Contains(analysis.Rows, r => r.IpAddress == "192.0.2.1" && r.Asn == 64500 && r.AsName.Contains("Example ASN A", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.Rows, r => r.IpAddress == "198.51.100.10" && r.Asn == 64501 && r.AsName.Contains("Example ASN B", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(analysis.Rows, r => r.IpAddress == "203.0.113.99" && r.Asn == 64502);

        Assert.Contains(analysis.Assessments, a => a.Code == IpEnrichmentCodes.ResultsPresent);
    }

    [Fact]
    public async Task CapsUniqueIpsAndSetsCappedAssessment()
    {
        var analysis = new IpEnrichmentAnalysis
        {
            IncludeMxHostAddresses = false,
            IncludeNsHostAddresses = false,
            MaxUniqueIpsToEnrich = 2,
            QueryOverride = (_, type, _) =>
            {
                if (type == DnsRecordType.A)
                {
                    return Task.FromResult(new[]
                    {
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.A, TTL = 300, DataRaw = "192.0.2.1" },
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.A, TTL = 300, DataRaw = "198.51.100.10" },
                        new DnsAnswer { Name = "example.com", Type = DnsRecordType.A, TTL = 300, DataRaw = "203.0.113.53" }
                    });
                }
                return Task.FromResult(Array.Empty<DnsAnswer>());
            },
            RdapQueryOverride = (_, _) => Task.FromResult<RdapIpNetwork?>(new RdapIpNetwork { Country = "US", Cidr = "0.0.0.0/0", Entities = Array.Empty<RdapEntity>() })
        };

        var logger = new InternalLogger();
        await analysis.AnalyzeAsync("example.com", logger: logger, cancellationToken: CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.True(analysis.ResultsCapped);
        Assert.Equal(2, analysis.UniqueIpCount);
        Assert.Contains(analysis.Assessments, a => a.Code == IpEnrichmentCodes.ResultsCapped);
    }
}

