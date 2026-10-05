using DnsClientX;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public partial class TestRevocationEvidence {
    [Fact]
    public async Task OversizedOcspDoesNotPreventAnIndependentAuthenticatedCrlVerdict() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var issuerKeys = Keys();
        var issuer = Certificate("CN=Issuer", BigInteger.One, issuerKeys, null, null, ca: true);
        var leaf = Certificate("CN=Leaf", BigInteger.Ten, Keys(), issuer, issuerKeys,
            ocspUrl: $"http://127.0.0.1:{port}/ocsp", crlUrl: $"http://127.0.0.1:{port}/crl");
        var crlGenerator = new X509V2CrlGenerator();
        crlGenerator.SetIssuerDN(issuer.SubjectDN);
        crlGenerator.SetThisUpdate(DateTime.UtcNow.AddMinutes(-1));
        crlGenerator.SetNextUpdate(DateTime.UtcNow.AddHours(1));
        byte[] crlBytes = crlGenerator.Generate(new Asn1SignatureFactory("SHA256WITHRSA", issuerKeys.Private)).GetEncoded();
        using var serverCancellation = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task server = ServeAsync();
        using var nativeLeaf = Load(leaf.GetEncoded());
        using var nativeIssuer = Load(issuer.GetEncoded());
        var analysis = new CertificateAnalysis { Certificate = nativeLeaf, Timeout = TimeSpan.FromSeconds(5) };
        analysis.Chain.Add(nativeLeaf); analysis.Chain.Add(nativeIssuer);
        try {
            var method = typeof(CertificateAnalysis).GetMethod("QueryRevocationEndpoints", BindingFlags.Instance | BindingFlags.NonPublic)!;
            await (Task)method.Invoke(analysis, new object[] { CancellationToken.None })!;
            Assert.Null(analysis.OcspRevoked);
            Assert.Equal(false, analysis.CrlRevoked);
        } finally {
            serverCancellation.Cancel(); listener.Stop();
            await server;
        }

        async Task ServeAsync() {
            try {
                while (true) {
                    using var client = await listener.AcceptTcpClientAsync().WaitWithCancellation(serverCancellation.Token);
                    using var stream = client.GetStream();
                    using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
                    string request = (await reader.ReadLineAsync().WaitWithCancellation(serverCancellation.Token))!;
                    while (!string.IsNullOrEmpty(await reader.ReadLineAsync().WaitWithCancellation(serverCancellation.Token))) { }
                    bool ocsp = request.Contains("/ocsp", StringComparison.Ordinal);
                    byte[] header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Length: {(ocsp ? 1048577 : crlBytes.Length)}\r\nConnection: close\r\n\r\n");
                    await stream.WriteAsync(header, 0, header.Length, serverCancellation.Token);
                    if (!ocsp) await stream.WriteAsync(crlBytes, 0, crlBytes.Length, serverCancellation.Token);
                }
            } catch (Exception) when (serverCancellation.IsCancellationRequested) { }
        }
    }

    private static X509Certificate2 Load(byte[] bytes) {
#if NET10_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(bytes);
#else
        return new X509Certificate2(bytes);
#endif
    }
}
