using DnsClientX;
using System;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDnsOverTlsAnalysis
{
    [Fact]
    public async Task FlagsNotSupportedWhenNoEndpointSupportsDoT()
    {
        var analysis = CreateAnalysis(supportDot: false);
        await analysis.Analyze("example.com", new InternalLogger(), CancellationToken.None);
        Assert.Contains(analysis.Assessments, a => a.Code == DnsOverTlsCodes.NotSupported && a.Severity == AssessmentSeverity.Warning);
    }

    [Fact]
    public async Task FlagsSupportedWhenAnyEndpointSupportsDoT()
    {
        var analysis = CreateAnalysis(supportDot: true);
        await analysis.Analyze("example.com", new InternalLogger(), CancellationToken.None);
        Assert.Contains(analysis.Assessments, a => a.Code == DnsOverTlsCodes.Supported && a.Severity == AssessmentSeverity.Info);
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == DnsOverTlsCodes.NotSupported && a.Severity == AssessmentSeverity.Warning);
    }

    private static DnsOverTlsAnalysis CreateAnalysis(bool supportDot)
    {
        return new DnsOverTlsAnalysis
        {
            QueryDnsOverride = (name, type) =>
            {
                if (type == DnsRecordType.NS && string.Equals(name, "example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(new[]
                    {
                        new DnsAnswer { DataRaw = "ns1.example.com", Type = DnsRecordType.NS },
                        new DnsAnswer { DataRaw = "ns2.example.com", Type = DnsRecordType.NS }
                    });
                }

                if (type == DnsRecordType.A && string.Equals(name, "ns1.example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "192.0.2.1", Type = DnsRecordType.A } });
                }

                if (type == DnsRecordType.A && string.Equals(name, "ns2.example.com", StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(new[] { new DnsAnswer { DataRaw = "192.0.2.2", Type = DnsRecordType.A } });
                }

                return Task.FromResult(Array.Empty<DnsAnswer>());
            },
            ProbeOverride = (nsHost, ip, port, timeout, ct) =>
            {
                _ = port;
                _ = timeout;
                ct.ThrowIfCancellationRequested();

                var ok = supportDot && ip.Equals(IPAddress.Parse("192.0.2.2"));
                return Task.FromResult(new DnsOverTlsEndpointResult
                {
                    NameServerHost = nsHost,
                    ServerIp = ip.ToString(),
                    Port = 853,
                    Supported = ok,
                    Protocol = ok ? "Tls13" : null,
                    CipherSuite = ok ? "TLS_AES_128_GCM_SHA256" : null,
                    HostnameMatch = ok,
                    CertificateValid = ok,
                    Error = ok ? null : "connection refused"
                });
            }
        };
    }
}
