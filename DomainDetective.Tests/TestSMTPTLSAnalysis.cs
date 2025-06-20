using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestSMTPTLSAnalysis {
        [Fact]
        public async Task DetectsTls12AndInvalidCert() {
            using var cert = CreateSelfSigned();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var ssl = new SslStream(client.GetStream());
                await ssl.AuthenticateAsServerAsync(cert, false, SslProtocols.Tls12, false);
                await Task.Delay(100);
            });

            try {
                var analysis = new SMTPTLSAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.Contains(SslProtocols.Tls12, result.SupportedProtocols);
                Assert.False(result.CertificateValid);
                Assert.True(result.DaysToExpire > 0);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        private static X509Certificate2 CreateSelfSigned() {
            using var ecdsa = ECDsa.Create();
            var req = new CertificateRequest("CN=localhost", ecdsa, HashAlgorithmName.SHA256);
            var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(30));
            return new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }
    }
}
