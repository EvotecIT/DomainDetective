using Xunit;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestMailTlsAnalysis
{
    [Fact]
    public async Task ImapTlsWorks()
    {
        using var cert = CreateSelfSigned();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource();
        var serverTask = Task.Run(() => RunImapServer(listener, cert, SslProtocols.Tls12, cts.Token), cts.Token);

        try
        {
            var analysis = new IMAPTLSAnalysis();
            await analysis.AnalyzeServer("localhost", port, new InternalLogger());
            var result = analysis.ServerResults[$"localhost:{port}"];
            Assert.True(result.StartTlsAdvertised);
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task Pop3TlsWorks()
    {
        using var cert = CreateSelfSigned();
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var cts = new CancellationTokenSource();
        var serverTask = Task.Run(() => RunPop3Server(listener, cert, SslProtocols.Tls12, cts.Token), cts.Token);

        try
        {
            var analysis = new POP3TLSAnalysis();
            await analysis.AnalyzeServer("localhost", port, new InternalLogger());
            var result = analysis.ServerResults[$"localhost:{port}"];
            Assert.True(result.StartTlsAdvertised);
        }
        finally
        {
            cts.Cancel();
            listener.Stop();
            await serverTask;
        }
    }

    private static async Task RunImapServer(TcpListener listener, X509Certificate2 cert, SslProtocols protocol, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var clientTask = listener.AcceptTcpClientAsync();
                var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                if (completed != clientTask)
                {
                    try { await clientTask; } catch { }
                    break;
                }

                var client = await clientTask;
                _ = Task.Run(async () =>
                {
                    using var tcp = client;
                    using var stream = tcp.GetStream();
                    using var reader = new StreamReader(stream);
                    using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                    await writer.WriteLineAsync("* OK IMAP4rev1");
                    await reader.ReadLineAsync();
                    await writer.WriteLineAsync("* CAPABILITY IMAP4rev1 STARTTLS\r\nA1 OK");
                    await reader.ReadLineAsync();
                    await writer.WriteLineAsync("A2 OK");
                    using var ssl = new SslStream(stream);
                    await ssl.AuthenticateAsServerAsync(cert, false, protocol, false);
                    using var sslReader = new StreamReader(ssl);
                    await sslReader.ReadLineAsync();
                }, token);
            }
        }
        catch
        {
            // ignore on shutdown
        }
    }

    private static async Task RunPop3Server(TcpListener listener, X509Certificate2 cert, SslProtocols protocol, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var clientTask = listener.AcceptTcpClientAsync();
                var completed = await Task.WhenAny(clientTask, Task.Delay(Timeout.Infinite, token));
                if (completed != clientTask)
                {
                    try { await clientTask; } catch { }
                    break;
                }

                var client = await clientTask;
                _ = Task.Run(async () =>
                {
                    using var tcp = client;
                    using var stream = tcp.GetStream();
                    using var reader = new StreamReader(stream);
                    using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                    await writer.WriteLineAsync("+OK POP3 ready");
                    await reader.ReadLineAsync();
                    await writer.WriteLineAsync("+OK\r\nSTLS\r\n.");
                    await reader.ReadLineAsync();
                    await writer.WriteLineAsync("+OK");
                    using var ssl = new SslStream(stream);
                    await ssl.AuthenticateAsServerAsync(cert, false, protocol, false);
                    using var sslReader = new StreamReader(ssl);
                    await sslReader.ReadLineAsync();
                }, token);
            }
        }
        catch
        {
            // ignore on shutdown
        }
    }

    private static X509Certificate2 CreateSelfSigned(string cn = "localhost")
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest($"CN={cn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(30));
        return new X509Certificate2(cert.Export(X509ContentType.Pfx));
    }
}
