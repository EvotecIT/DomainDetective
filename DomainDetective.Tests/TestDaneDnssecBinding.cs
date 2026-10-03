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
    [InlineData(true, false, DaneAuthenticationStatus.Authenticated)]
    [InlineData(false, false, DaneAuthenticationStatus.Inconclusive)]
    [InlineData(false, true, DaneAuthenticationStatus.Inconclusive)]
    public async Task LiveTlsAuthenticationUsesTheSameValidatedTlsaData(bool sameRecord, bool unrelatedOwner, DaneAuthenticationStatus expected) {
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
            using var check = new DomainHealthCheck { OutboundAddressResolver = (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback }) };
            int tlsaQueries = 0;
            check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
                var response = new DnsResponse { Status = DnsResponseCode.NoError };
                if (type == DnsRecordType.TLSA) {
                    int query = Interlocked.Increment(ref tlsaQueries);
                    response.Answers = new[] { new DnsAnswer { Name = owner, Type = type, DataRaw = "3 0 1 " + (query == 1 || sameRecord ? digest : new string('0', 64)) } };
                    if (query > 1 && unrelatedOwner) response.Answers = response.Answers.Append(new DnsAnswer {
                        Name = $"_{port}._tcp.unrelated.example", Type = type, DataRaw = "3 0 1 " + digest
                    }).ToArray();
                    typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!
                        .SetValue(response, query > 1 ? DnsSecValidationStatus.Secure : DnsSecValidationStatus.NotRequested);
                }
                return Task.FromResult(response);
            };
            await check.VerifyDANE("example.com", new[] { port }, guard.Token);
            await server;
            Assert.Equal(2, tlsaQueries);
            Assert.Equal(expected, Assert.Single(check.DaneAnalysis.AnalysisResults).AuthenticationStatus);
            Assert.Equal(sameRecord, check.DaneAnalysis.AllServicesAuthenticated);
        } finally {
            guard.Cancel();
            listener.Stop();
        }
    }
}
#endif
