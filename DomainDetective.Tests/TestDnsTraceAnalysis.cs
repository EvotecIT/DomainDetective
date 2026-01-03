using DnsClientX;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDnsTraceAnalysis
{
    [Fact]
    public async Task FollowsReferralsUsingAdditionalAddresses()
    {
        var analysis = new DnsTraceAnalysis
        {
            RecordTypesToTrace = new[] { DnsRecordType.A },
            QueryOverride = (server, name, type, _) =>
            {
                if (type != DnsRecordType.A)
                {
                    return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
                }

                if (server == "192.0.2.10")
                {
                    return Task.FromResult(new DnsResponse
                    {
                        Status = DnsResponseCode.NoError,
                        Authorities = new[]
                        {
                            new DnsAnswer { Name = "example.com", Type = DnsRecordType.NS, TTL = 3600, DataRaw = "ns1.example.net." }
                        },
                        Additional = new[]
                        {
                            new DnsAnswer { Name = "ns1.example.net", Type = DnsRecordType.A, TTL = 3600, DataRaw = "192.0.2.20" }
                        }
                    });
                }

                if (server == "192.0.2.20")
                {
                    return Task.FromResult(new DnsResponse
                    {
                        Status = DnsResponseCode.NoError,
                        Answers = new[]
                        {
                            new DnsAnswer { Name = "example.com", Type = DnsRecordType.A, TTL = 300, DataRaw = "192.0.2.1" }
                        }
                    });
                }

                // Root hop: refer to a "TLD server" via Additional A record.
                return Task.FromResult(new DnsResponse
                {
                    Status = DnsResponseCode.NoError,
                    Authorities = new[]
                    {
                        new DnsAnswer { Name = "com", Type = DnsRecordType.NS, TTL = 172800, DataRaw = "a.gtld-servers.net." }
                    },
                    Additional = new[]
                    {
                        new DnsAnswer { Name = "a.gtld-servers.net", Type = DnsRecordType.A, TTL = 172800, DataRaw = "192.0.2.10" }
                    }
                });
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.TraceSucceeded);
        Assert.Equal(1, analysis.TraceQueries);
        Assert.Equal(0, analysis.TraceQueriesFailed);
        Assert.Equal(3, analysis.TotalSteps);

        var q = Assert.Single(analysis.Queries);
        Assert.Equal(DnsTraceQueryStatus.Success, q.Status);
        Assert.Equal(DnsResponseCode.NoError, q.FinalResponseStatus);
        Assert.Equal("example.com", q.FinalName);
        Assert.Contains(q.Steps, s => s.NextServers.Contains("192.0.2.10", StringComparer.OrdinalIgnoreCase));
        Assert.Contains(analysis.Assessments, a => a.Code == DnsTraceCodes.ResultsPresent);
    }

    [Fact]
    public async Task UsesNameServerLookupWhenReferralHasNoAdditional()
    {
        var analysis = new DnsTraceAnalysis
        {
            RecordTypesToTrace = new[] { DnsRecordType.A },
            QueryOverride = (server, name, type, _) =>
            {
                if (type != DnsRecordType.A)
                {
                    return Task.FromResult(new DnsResponse { Status = DnsResponseCode.NoError });
                }

                if (server == "192.0.2.10")
                {
                    return Task.FromResult(new DnsResponse
                    {
                        Status = DnsResponseCode.NoError,
                        Authorities = new[]
                        {
                            new DnsAnswer { Name = "example.com", Type = DnsRecordType.NS, TTL = 3600, DataRaw = "ns1.example.net." }
                        },
                        Additional = new[]
                        {
                            new DnsAnswer { Name = "ns1.example.net", Type = DnsRecordType.A, TTL = 3600, DataRaw = "192.0.2.20" }
                        }
                    });
                }

                if (server == "192.0.2.20")
                {
                    return Task.FromResult(new DnsResponse
                    {
                        Status = DnsResponseCode.NoError,
                        Answers = new[]
                        {
                            new DnsAnswer { Name = "example.com", Type = DnsRecordType.A, TTL = 300, DataRaw = "192.0.2.1" }
                        }
                    });
                }

                if (name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
                {
                    // Simulate "resolving" the NS host to an IP so the trace can continue.
                    return Task.FromResult(new DnsResponse
                    {
                        Status = DnsResponseCode.NoError,
                        Answers = new[]
                        {
                            new DnsAnswer { Name = "a.gtld-servers.net", Type = DnsRecordType.A, TTL = 172800, DataRaw = "192.0.2.10" }
                        }
                    });
                }

                // Root hop: referral without Additional; forces NameServerLookup path.
                return Task.FromResult(new DnsResponse
                {
                    Status = DnsResponseCode.NoError,
                    Authorities = new[]
                    {
                        new DnsAnswer { Name = "com", Type = DnsRecordType.NS, TTL = 172800, DataRaw = "a.gtld-servers.net." }
                    }
                });
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        var q = Assert.Single(analysis.Queries);
        Assert.Equal(DnsTraceQueryStatus.Success, q.Status);
        Assert.Equal("example.com", q.FinalName);
        Assert.Contains(q.Steps, s => s.Kind == DnsTraceStepKind.NameServerLookup);
    }
}

