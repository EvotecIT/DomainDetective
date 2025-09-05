using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using DomainDetective.Narratives;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests {
    [Collection("HttpListener")]
    public class TestHpkpNarrative {
        [Fact]
        public async Task BuildsNarrativeAndPositives() {
            Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
            using var listener = new HttpListener();
            var port = PortHelper.GetFreePort();
            var prefix = $"http://localhost:{port}/";
            listener.Prefixes.Add(prefix);
            listener.Start();
            PortHelper.ReleasePort(port);
            var pin1 = Convert.ToBase64String(Enumerable.Repeat((byte)1, 32).ToArray());
            var pin2 = Convert.ToBase64String(Enumerable.Repeat((byte)2, 32).ToArray());
            var header = $"pin-sha256=\"{pin1}\"; pin-sha256=\"{pin2}\"; max-age=100; includeSubDomains";
            var task = Task.Run(async () => {
                var ctx = await listener.GetContextAsync();
                ctx.Response.Headers.Add("Public-Key-Pins", header);
                var buffer = Encoding.UTF8.GetBytes("ok");
                await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
                ctx.Response.Close();
            });
            try {
                var analysis = new HPKPAnalysis();
                await analysis.AnalyzeUrl(prefix, new InternalLogger());
                var sections = HpkpNarrative.Build(analysis);
                Assert.Contains(sections.Highlights, h => h.Contains("header present"));
                Assert.Contains(sections.Highlights, h => h.Contains("includeSubDomains"));
                var positives = RecommendationEngine.FromPositives(analysis.Assessments);
                Assert.Contains(positives, p => p.Code == HpkpCodes.PinsValid);
                Assert.Contains(positives, p => p.Code == HpkpCodes.IncludeSubDomains);
            } finally {
                listener.Stop();
                await task;
            }
        }
    }
}
