#if NET8_0_OR_GREATER
using DnsClientX;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.Tests;

public class TestDaneDnssecBinding {
    [Theory]
    [InlineData("ports")]
    [InlineData("services")]
    [InlineData("https")]
    [InlineData("smtp-mx")]
    public async Task ResolverFailureDoesNotClaimTlsaAbsence(string route) {
        using var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsResponseOverride = (_, _, _) =>
            Task.FromResult(new DnsResponse { Status = DnsResponseCode.ServerFailure });

        switch (route) {
            case "ports":
                await check.VerifyDANE("example.com", new[] { 443 });
                break;
            case "services":
                await check.VerifyDANE(new[] { new ServiceDefinition("example.com", 443) });
                break;
            case "https":
                await check.VerifyDANE("example.com", new[] { ServiceType.HTTPS });
                break;
            default:
                await check.VerifyDANE("example.com", new[] { ServiceType.SMTP });
                break;
        }

        Assert.True(check.DaneAnalysis.DnsQueryFailed);
        Assert.Single(check.DaneAnalysis.FailedDnsQueries);
        Assert.Contains(check.DaneAnalysis.Assessments, assessment => assessment.Code == DaneCodes.QueryFailed);
        Assert.DoesNotContain(check.DaneAnalysis.Assessments, assessment => assessment.Code == DaneCodes.NoRecords);
        Assert.DoesNotContain(DomainDetective.Narratives.DaneNarrative.Build(check.DaneAnalysis).Highlights,
            highlight => highlight == "No TLSA records published.");
        var view = DomainDetective.Views.Converters.Convert(check.DaneAnalysis);
        Assert.True(view.DnsQueryFailed);
        Assert.Equal("Query failed", Assert.Single(
            DomainDetective.Views.Converters.ConvertDomainOverview(check, "example.com").MailDnsChecks,
            status => status.Key == "dane").Value);
        Assert.Equal("Query failed", Assert.Single(
            DomainDetective.Views.Converters.ConvertMicrosoft365Overview(check, "example.com").MailDnsChecks,
            status => status.Key == "dane").Value);
    }

    [Theory]
    [InlineData("same", DaneAuthenticationStatus.Authenticated)]
    [InlineData("changed", DaneAuthenticationStatus.Inconclusive)]
    [InlineData("foreign-extra", DaneAuthenticationStatus.Inconclusive)]
    [InlineData("foreign-only", DaneAuthenticationStatus.NotChecked)]
    [InlineData("alias", DaneAuthenticationStatus.Authenticated)]
    [InlineData("mixed-foreign", DaneAuthenticationStatus.Authenticated)]
    public async Task LiveTlsAuthenticationUsesTheSameValidatedTlsaData(string scenario, DaneAuthenticationStatus expected) {
        bool sameRecord = scenario == "same" || scenario == "alias" || scenario == "foreign-only" || scenario == "mixed-foreign";
        using RSA key = RSA.Create(2048);
        var request = new CertificateRequest("CN=example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        byte[] pfx = created.Export(X509ContentType.Pfx);
#if NET9_0_OR_GREATER
        using X509Certificate2 certificate = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
#else
        using X509Certificate2 certificate = new(pfx, (string?)null, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
#endif
        using var sha = SHA256.Create();
        string digest = BitConverter.ToString(sha.ComputeHash(certificate.RawData)).Replace("-", string.Empty);
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string owner = $"_{port}._tcp.example.com";
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task server = Task.Run(async () => {
            using var connection = await listener.AcceptTcpClientAsync(guard.Token);
            using var tls = new SslStream(connection.GetStream(), false);
            await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions {
                ServerCertificate = certificate, EnabledSslProtocols = SslProtocols.Tls12
            }, guard.Token);
        }, guard.Token);
        try {
            var outboundHosts = new List<string>();
            using var check = new DomainHealthCheck { OutboundAddressResolver = (host, _) => {
                outboundHosts.Add(host);
                return Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback });
            } };
            int tlsaQueries = 0;
            check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
                var response = new DnsResponse { Status = DnsResponseCode.NoError };
                if (type == DnsRecordType.TLSA) {
                    int query = Interlocked.Increment(ref tlsaQueries);
                    string answerOwner = scenario == "foreign-only" || scenario == "alias" ||
                        (scenario == "mixed-foreign" && name != owner) ? $"_{port}._tcp.unrelated.example" : owner;
                    response.Answers = new[] { new DnsAnswer { Name = answerOwner, Type = type, DataRaw = "3 0 1 " + (query == 1 || sameRecord ? digest : new string('0', 64)) } };
                    if (query > 1 && scenario == "foreign-extra") response.Answers = response.Answers.Append(new DnsAnswer {
                        Name = $"_{port}._tcp.unrelated.example", Type = type, DataRaw = "3 0 1 " + digest
                    }).ToArray();
                    if (scenario == "alias") typeof(DnsResponse).GetProperty(nameof(DnsResponse.RequestedAnswerPresent))!.SetValue(response, true);
                    typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!
                        .SetValue(response, query > 1 ? DnsSecValidationStatus.Secure : DnsSecValidationStatus.NotRequested);
                } else if (type == DnsRecordType.CNAME) {
                    typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!
                        .SetValue(response, DnsSecValidationStatus.Secure);
                }
                return Task.FromResult(response);
            };
            if (scenario == "mixed-foreign") {
                await check.VerifyDANE(new[] {
                    new ServiceDefinition("example.com", port), new ServiceDefinition("other.example", port)
                }, guard.Token);
            } else {
                await check.VerifyDANE("example.com", new[] { port }, guard.Token);
            }
            if (scenario == "foreign-only") {
                Assert.Empty(check.DaneAnalysis.AnalysisResults);
                Assert.Empty(outboundHosts);
                Assert.Equal(1, tlsaQueries);
                Assert.False(check.DaneAnalysis.AllServicesAuthenticated);
            } else {
                await server;
                Assert.Equal(scenario == "mixed-foreign" ? 3 : 2, tlsaQueries);
                Assert.Equal(expected, Assert.Single(check.DaneAnalysis.AnalysisResults).AuthenticationStatus);
                Assert.Equal(owner, Assert.Single(check.DaneAnalysis.AnalysisResults).DomainName);
                Assert.Contains("example.com", outboundHosts);
                Assert.DoesNotContain("unrelated.example", outboundHosts);
                Assert.Equal(sameRecord && scenario != "mixed-foreign", check.DaneAnalysis.AllServicesAuthenticated);
            }
        } finally {
            guard.Cancel();
            listener.Stop();
            try { await server; }
            catch (Exception exception) when (guard.IsCancellationRequested && (exception is OperationCanceledException || exception is SocketException)) { }
        }
    }

    [Theory]
    [InlineData("services")]
    [InlineData("service-type")]
    public async Task ForeignTlsaOwnerCannotAuthenticateAnExplicitOrNamedService(string route) {
        using var check = new DomainHealthCheck();
        int queries = 0;
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            var response = new DnsResponse { Status = DnsResponseCode.NoError };
            if (type == DnsRecordType.TLSA) {
                Interlocked.Increment(ref queries);
                response.Answers = new[] { new DnsAnswer {
                    Name = "_443._tcp.unrelated.example", Type = DnsRecordType.TLSA,
                    DataRaw = "3 1 1 " + new string('A', 64)
                } };
            } else {
                Assert.Equal(DnsRecordType.CNAME, type);
            }
            typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!
                .SetValue(response, DnsSecValidationStatus.Secure);
            return Task.FromResult(response);
        };

        if (route == "services") {
            await check.VerifyDANE(new[] { new ServiceDefinition("example.com", 443) });
        } else {
            await check.VerifyDANE("example.com", new[] { ServiceType.HTTPS });
        }

        Assert.Equal(1, queries);
        Assert.Equal("_443._tcp.example.com", Assert.Single(check.DaneAnalysis.QueriedNames));
        Assert.Empty(check.DaneAnalysis.AnalysisResults);
        Assert.False(check.DaneAnalysis.DnsQueryFailed);
        Assert.Contains(check.DaneAnalysis.Assessments, assessment => assessment.Code == DaneCodes.NoRecords);
        Assert.False(check.DaneAnalysis.AllServicesAuthenticated);
    }
}
#endif
