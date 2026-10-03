using RichardSzalay.MockHttp;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestCspPolicyContract {
    [Theory]
    [InlineData("script-src 'unsafe-inline'; frame-ancestors 'none'", true)]
    [InlineData("frame-ancestors 'none'; script-src 'unsafe-inline'", true)]
    [InlineData("script-src 'unsafe-inline'; frame-ancestors-invalid 'none'", false)]
    public async Task AllDirectiveFactsAreReported(string policy, bool frameAncestors) {
        using var handler = new MockHttpMessageHandler();
        handler.When("https://example.com/").Respond(_ => {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok") };
            response.Headers.TryAddWithoutValidation("Content-Security-Policy", policy);
            return response;
        });
        var analysis = new HttpAnalysis { HttpHandlerFactory = () => handler };
        await analysis.AnalyzeUrl("https://example.com/", true, new InternalLogger(), collectHeaders: true);
        Assert.True(analysis.CspUnsafeDirectives);
        Assert.Equal(frameAncestors, analysis.CspFrameAncestorsPresent);
        Assert.Equal(!frameAncestors, analysis.MissingSecurityHeaders.Contains("X-Frame-Options"));
    }
}
