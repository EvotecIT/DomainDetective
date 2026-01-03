using DnsClientX;
using System;
using System.Collections.Generic;
using System.Net;

namespace DomainDetective.Tests;

public sealed class TestDnsPropagationReportAnalysis
{
    [Fact]
    public void DetectsNonPublicIpAndSplitHorizon()
    {
        var results = new List<DnsPropagationResult>
        {
            new DnsPropagationResult
            {
                RecordType = DnsRecordType.A,
                Duration = TimeSpan.FromMilliseconds(10),
                Success = true,
                Records = new[] { "10.0.0.1" },
                Server = new PublicDnsEntry
                {
                    IPAddress = IPAddress.Parse("1.1.1.1"),
                    HostName = "one.one.one.one"
                }
            },
            new DnsPropagationResult
            {
                RecordType = DnsRecordType.A,
                Duration = TimeSpan.FromMilliseconds(12),
                Success = true,
                Records = new[] { "93.184.216.34" },
                Server = new PublicDnsEntry
                {
                    IPAddress = IPAddress.Parse("8.8.8.8"),
                    HostName = "dns.google"
                }
            }
        };

        var report = new DnsPropagationReportAnalysis();
        report.Load("example.com", DnsRecordType.A, results);

        Assert.Contains(report.Assessments, a => a.Code == DnsPropagationCodes.NonPublicIpAddress);
        Assert.Contains(report.Assessments, a => a.Code == DnsPropagationCodes.SplitHorizonSuspected);
    }
}

