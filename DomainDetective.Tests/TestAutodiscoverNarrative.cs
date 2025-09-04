using DnsClientX;
using DomainDetective.Narratives;
using DomainDetective.Recommendations;
using RichardSzalay.MockHttp;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestAutodiscoverNarrative {
    [Fact]
    public async Task BuildsNarrativeWithHighlightsAndPositives() {
        var answers = new List<DnsAnswer> {
            new DnsAnswer { DataRaw = "0 0 443 autodiscover.example.com", Type = DnsRecordType.SRV }
        };
        var cnames = new List<DnsAnswer> {
            new DnsAnswer { DataRaw = "mail.example.com", Type = DnsRecordType.CNAME }
        };
        var analysis = new AutodiscoverAnalysis();
        analysis.QueryDnsOverride = (name, type) => {
            if (type == DnsRecordType.SRV) return Task.FromResult(answers.ToArray());
            if (type == DnsRecordType.CNAME) return Task.FromResult(cnames.ToArray());
            return Task.FromResult(Array.Empty<DnsAnswer>());
        };
        await analysis.Analyze("example.com", new DnsConfiguration(), new InternalLogger());

        var mock = new MockHttpMessageHandler();
        mock.When("https://autodiscover.example.com/autodiscover/autodiscover.xml")
            .Respond("application/xml", "<Autodiscover></Autodiscover>");
        var http = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => mock };
        await http.Analyze("example.com", new InternalLogger());
        analysis.SetHttpEndpoints(http.Endpoints);

        var sections = AutodiscoverNarrative.Build(analysis, analysis.Assessments.Concat(http.Assessments));
        Assert.Contains(sections.Highlights, h => h.Contains("SRV"));
        Assert.Contains(sections.Highlights, h => h.Contains("valid Autodiscover XML"));
        Assert.NotEmpty(sections.Positives);
    }
}
