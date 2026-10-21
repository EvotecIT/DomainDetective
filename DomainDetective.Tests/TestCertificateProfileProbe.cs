using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using Xunit;

namespace DomainDetective.Tests;

[Collection("FtpTlsProtocol")]
public sealed class TestCertificateProfileProbe {
    [Fact]
    public void StandardProfilesKeepBaselineAndProtocolModesExplicit() {
        var profiles = CertificateProbeProfile.StandardProfiles();
        Assert.Equal(6, profiles.Count);
        Assert.Equal("https-443", Assert.Single(CertificateProbeProfile.Resolve(profiles)).Id);
        Assert.Equal(CertificateProbeTransport.SmtpStartTls, profiles.Single(p => p.Port == 25).Transport);
        Assert.Equal(CertificateProbeTransport.FtpExplicitTls, profiles.Single(p => p.Port == 21).Transport);
        Assert.Equal(CertificateProbeTransport.FtpImplicitTls, profiles.Single(p => p.Port == 990).Transport);
        Assert.Equal("ldaps", profiles.Single(p => p.Port == 636).Service);
        Assert.Throws<ArgumentException>(() => CertificateProbeProfile.Resolve(new[] { profiles[0], profiles[0] }));
        Assert.Throws<ArgumentException>(() => new CertificateProbeProfile { Id = "smtp", Port = 465, Transport = CertificateProbeTransport.SmtpStartTls }.Validate());
    }

    [Fact]
    public async Task ProfileDispatcherNegotiatesEachProtocolBeforeTlsAndReturnsTheProfile() {
        foreach (CertificateProbeProfile profile in CertificateProbeProfile.StandardProfiles()) await ProbeFixture(profile);
    }

    [Fact]
    public async Task ProtocolFailureKeepsConnectionRefusedInsteadOfBecomingATlsHandshakeFailure() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        foreach (var mode in new[] { CertificateProbeTransport.SmtpStartTls, CertificateProbeTransport.FtpExplicitTls, CertificateProbeTransport.FtpImplicitTls }) {
            var profile = new CertificateProbeProfile { Id = "closed-service", Port = port, Transport = mode };
            var error = await Assert.ThrowsAsync<TlsProbe.TlsProbeException>(() => CertificateProfileProbe.ProbeAsync("127.0.0.1", profile, TimeSpan.FromSeconds(3)));
            Assert.Equal(CertificateFailureKind.ConnectionRefused, TlsFailureClassification.Classify(error));
            Assert.Null(error.RemoteAddress);
            Assert.Null(error.RemotePort);
        }
    }

    private static async Task ProbeFixture(CertificateProbeProfile standard) {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        using X509Certificate2 source = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using X509Certificate2 certificate = CertificateLoaderCompat.LoadPkcs12(source.Export(X509ContentType.Pfx));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task peer = Task.Run(async () => {
            using TcpClient client = await listener.AcceptTcpClientAsync().WaitWithCancellation(guard.Token);
            using NetworkStream network = client.GetStream();
            if (standard.Transport is CertificateProbeTransport.SmtpStartTls or CertificateProbeTransport.FtpExplicitTls) {
                using var reader = new StreamReader(network, Encoding.ASCII, false, 1024, true);
                using var writer = new StreamWriter(network, Encoding.ASCII, 1024, true) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 localhost ready");
                if (standard.Transport == CertificateProbeTransport.SmtpStartTls) {
                    Assert.StartsWith("EHLO ", await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
                    await writer.WriteLineAsync("250 STARTTLS");
                    Assert.Equal("STARTTLS", await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
                    await writer.WriteLineAsync("220 Begin TLS");
                } else {
                    Assert.Equal("AUTH TLS", await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
                    await writer.WriteLineAsync("234 AUTH TLS accepted");
                }
            }
            using var ssl = new SslStream(network, true);
            await ssl.AuthenticateAsServerAsync(certificate, false, SslProtocols.Tls12, false).WaitWithCancellation(guard.Token);
            if (standard.Transport == CertificateProbeTransport.SmtpStartTls) {
                using var reader = new StreamReader(ssl, Encoding.ASCII, false, 1024, true);
                Assert.Equal("QUIT", await reader.ReadLineAsync().WaitWithCancellation(guard.Token));
            }
            await release.Task.WaitWithCancellation(guard.Token);
        });
        try {
            var profile = new CertificateProbeProfile { Id = standard.Id, Port = port, Transport = standard.Transport, Service = standard.Service };
            using TlsProbe.Result result = await CertificateProfileProbe.ProbeAsync("localhost", profile, TimeSpan.FromSeconds(10), guard.Token);
            Assert.Equal(standard.Id, result.ProfileId);
            Assert.Equal(standard.Service, result.EndpointService);
            Assert.Equal(port, result.RemotePort);
            Assert.Equal(IPAddress.Loopback, result.RemoteAddress);
            Assert.NotNull(result.Certificate);
            Assert.Equal(certificate.Thumbprint, result.Certificate!.Thumbprint);
            Assert.True(result.HostnameMatch);
            Assert.False(result.ChainValid);
            Assert.Equal(SslProtocols.Tls12, result.Protocol);
        } finally {
            release.TrySetResult(true);
            listener.Stop();
            await peer;
        }
    }
}
