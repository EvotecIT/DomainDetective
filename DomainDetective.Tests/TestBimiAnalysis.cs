using DnsClientX;
using System.Net;
using System.Text;

namespace DomainDetective.Tests {
    public class TestBimiAnalysis {
        [Fact]
        public async Task ParseBimiRecord() {
            var record = "v=BIMI1; l=https://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg";
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = record,
                    Type = DnsRecordType.TXT
                }
            };
            var analysis = new BimiAnalysis();
            await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

            Assert.True(analysis.BimiRecordExists);
            Assert.True(analysis.StartsCorrectly);
            Assert.Equal("https://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg", analysis.Location);
            Assert.True(analysis.LocationUsesHttps);
            Assert.True(analysis.SvgFetched);
            Assert.True(analysis.SvgValid);
        }

        [Fact]
        public async Task ParseBimiRecordHttp() {
            var record = "v=BIMI1; l=http://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg";
            var answers = new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = record,
                    Type = DnsRecordType.TXT
                }
            };
            var logger = new InternalLogger();
            var warnings = new List<LogEventArgs>();
            logger.OnWarningMessage += (_, e) => warnings.Add(e);
            var analysis = new BimiAnalysis();
            await analysis.AnalyzeBimiRecords(answers, logger);

            Assert.True(analysis.BimiRecordExists);
            Assert.True(analysis.StartsCorrectly);
            Assert.Equal("http://upload.wikimedia.org/wikipedia/commons/a/a7/React-icon.svg", analysis.Location);
            Assert.False(analysis.LocationUsesHttps);
            Assert.True(analysis.SvgFetched);
            Assert.True(analysis.SvgValid);
            Assert.Contains(warnings, w => w.FullMessage.Contains("does not use HTTPS"));
        }

        [Fact]
        public async Task InvalidSvgFailsValidation() {
            using var listener = new HttpListener();
            var prefix = $"http://localhost:{GetFreePort()}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            var serverTask = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "image/svg+xml";
                var buffer = Encoding.UTF8.GetBytes("<html></html>");
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            });

            try {
                var record = $"v=BIMI1; l={prefix}logo.svg";
                var answers = new List<DnsAnswer> {
                    new DnsAnswer { DataRaw = record, Type = DnsRecordType.TXT }
                };
                var analysis = new BimiAnalysis();
                await analysis.AnalyzeBimiRecords(answers, new InternalLogger());

                Assert.True(analysis.SvgFetched);
                Assert.False(analysis.SvgValid);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        private static int GetFreePort() {
            var socket = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            socket.Start();
            var port = ((IPEndPoint)socket.LocalEndpoint).Port;
            socket.Stop();
            return port;
        }
    }
}