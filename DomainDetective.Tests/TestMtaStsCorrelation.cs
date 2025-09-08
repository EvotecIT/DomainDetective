using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Security.Authentication;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestMtaStsCorrelation
{
    private static (DomainHealthCheck hc, int port, HttpListener listener) CreateHealthCheckWithPolicyServer(string domain, string[] mxHosts, string policyText)
    {
        var hc = new DomainHealthCheck(DnsEndpoint.System, new InternalLogger());
        // DNS overrides: _mta-sts TXT and MX hosts
        hc.DnsConfiguration.QueryDnsOverride = (name, type) =>
        {
            if (type == DnsClientX.DnsRecordType.TXT && string.Equals(name, "_mta-sts." + domain, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new[] { new DnsClientX.DnsAnswer { Type = DnsClientX.DnsRecordType.TXT, DataRaw = "v=STSv1; id=12345" } });
            }
            if (type == DnsClientX.DnsRecordType.MX && string.Equals(name, domain, StringComparison.OrdinalIgnoreCase))
            {
                var answers = mxHosts.Select((h, i) => new DnsClientX.DnsAnswer { Type = DnsClientX.DnsRecordType.MX, DataRaw = $"{10 + i} {h}." }).ToArray();
                return Task.FromResult(answers);
            }
            return Task.FromResult(Array.Empty<DnsClientX.DnsAnswer>());
        };

        // Minimal HTTP policy server (HTTP is acceptable for tests via PolicyUrlOverride)
        var port = PortHelper.GetFreePort();
        var listener = new HttpListener();
        var prefix = $"http://localhost:{port}/.well-known/";
        listener.Prefixes.Add(prefix);
        listener.Start();
        PortHelper.ReleasePort(port);
        _ = Task.Run(async () =>
        {
            var ctx = await listener.GetContextAsync();
            ctx.Response.StatusCode = 200;
            var buffer = Encoding.UTF8.GetBytes(policyText);
            await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            ctx.Response.Close();
        });

        // Point MTA-STS fetch to the local listener
        hc.MtaStsPolicyUrlOverride = $"http://localhost:{port}/.well-known/mta-sts.txt";
        return (hc, port, listener);
    }

    [Fact]
    public async Task AllMxModernTls_YieldsModernAllPositive()
    {
        var domain = "example.com";
        var mx = new[] { "mx1.example.com", "mx2.example.com" };
        var policy = "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mx1.example.com\nmx: mx2.example.com\n";
        var (hc, port, listener) = CreateHealthCheckWithPolicyServer(domain, mx, policy);
        try
        {
            // Prepopulate SMTP TLS results to avoid network probes
            foreach (var host in mx)
            {
                hc.SmtpTlsAnalysis.ServerResults[$"{host}:25"] = new MailTlsAnalysis.TlsResult
                {
                    StartTlsAdvertised = true,
                    Protocol = SslProtocols.Tls12,
                    Tls13Used = false,
                    LegacyEnabled = false,
                    CertificateValid = true,
                    HostnameMatch = true,
                    GradeLevel = GradeLevel.B,
                };
            }

            await hc.VerifyMTASTS(domain);

            var codes = hc.MTASTSAnalysis.Assessments.Select(a => a.Code).ToArray();
            Assert.Contains(MtaStsCodes.MxTlsModernAll, codes);
            Assert.DoesNotContain(MtaStsCodes.MxStartTlsMissing, codes);
            Assert.DoesNotContain(MtaStsCodes.MxTlsWeak, codes);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task MissingStartTls_YieldsWarning()
    {
        var domain = "example.com";
        var mx = new[] { "mx1.example.com", "mx2.example.com" };
        var policy = "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mx1.example.com\nmx: mx2.example.com\n";
        var (hc, port, listener) = CreateHealthCheckWithPolicyServer(domain, mx, policy);
        try
        {
            hc.SmtpTlsAnalysis.ServerResults[$"{mx[0]}:25"] = new MailTlsAnalysis.TlsResult
            {
                StartTlsAdvertised = true,
                Protocol = SslProtocols.Tls12,
                LegacyEnabled = false,
                CertificateValid = true,
                HostnameMatch = true,
                GradeLevel = GradeLevel.B,
            };
            hc.SmtpTlsAnalysis.ServerResults[$"{mx[1]}:25"] = new MailTlsAnalysis.TlsResult
            {
                StartTlsAdvertised = false,
                Protocol = SslProtocols.Tls12,
                LegacyEnabled = false,
                CertificateValid = true,
                HostnameMatch = true,
                GradeLevel = GradeLevel.B,
            };

            await hc.VerifyMTASTS(domain);
            var codes = hc.MTASTSAnalysis.Assessments.Select(a => a.Code).ToArray();
            Assert.Contains(MtaStsCodes.MxStartTlsMissing, codes);
            Assert.DoesNotContain(MtaStsCodes.MxTlsModernAll, codes);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task WeakTls_YieldsWarning()
    {
        var domain = "example.com";
        var mx = new[] { "mx1.example.com", "mx2.example.com" };
        var policy = "version: STSv1\nmode: enforce\nmax_age: 86400\nmx: mx1.example.com\nmx: mx2.example.com\n";
        var (hc, port, listener) = CreateHealthCheckWithPolicyServer(domain, mx, policy);
        try
        {
            hc.SmtpTlsAnalysis.ServerResults[$"{mx[0]}:25"] = new MailTlsAnalysis.TlsResult
            {
                StartTlsAdvertised = true,
                Protocol = SslProtocols.Tls12,
                LegacyEnabled = false,
                CertificateValid = true,
                HostnameMatch = true,
                GradeLevel = GradeLevel.B,
            };
            // Weak: legacy enabled and low grade
            hc.SmtpTlsAnalysis.ServerResults[$"{mx[1]}:25"] = new MailTlsAnalysis.TlsResult
            {
                StartTlsAdvertised = true,
                Protocol = SslProtocols.Tls,
                LegacyEnabled = true,
                CertificateValid = true,
                HostnameMatch = true,
                GradeLevel = GradeLevel.D,
            };

            await hc.VerifyMTASTS(domain);
            var codes = hc.MTASTSAnalysis.Assessments.Select(a => a.Code).ToArray();
            Assert.Contains(MtaStsCodes.MxTlsWeak, codes);
            Assert.DoesNotContain(MtaStsCodes.MxTlsModernAll, codes);
        }
        finally
        {
            listener.Stop();
        }
    }
}

