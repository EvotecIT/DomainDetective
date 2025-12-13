using System.Collections.Generic;
using System.Net.Http;
using Xunit;

namespace DomainDetective.Tests;

public class TestTechSignatureParsing
{
    [Fact]
    public void HeaderRules_Extracts_Versions_From_Common_Headers()
    {
        var resp = new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        resp.Headers.TryAddWithoutValidation("Server", "Apache/2.4.57");
        resp.Headers.TryAddWithoutValidation("X-Powered-By", "PHP/7.4.33");
        var set = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        var details = new List<TechDetectionDetail>();
        TechSignatureCatalog.ApplyHeadersCookiesMeta(resp, body: null, outTech: set, details: details);
        Assert.Contains("PHP", set);
        Assert.Contains(details, d => d.Name == "PHP" && d.Version == "7.4.33");
    }

    [Fact]
    public void PathRules_Extracts_JQueryMigrate_Version()
    {
        var requests = new List<DomainDetective.WebStaticScanAnalysis.StaticRequest>
        {
            new DomainDetective.WebStaticScanAnalysis.StaticRequest { Url = "https://example.com/js/jquery-migrate.min.js?ver=3.3.2", FinalUrl = "https://example.com/js/jquery-migrate.min.js?ver=3.3.2", ContentType = "application/javascript", Method = "HEAD", StatusCode = 200, Host = "example.com" }
        };
        var hosts = new Dictionary<string, DomainDetective.WebStaticScanAnalysis.StaticHost>
        {
            ["example.com"] = new DomainDetective.WebStaticScanAnalysis.StaticHost { Host = "example.com" }
        };
        var set = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        var details = new List<TechDetectionDetail>();
        TechSignatureCatalog.ApplyPathsDomainsBody(requests, hosts, body: null, getRegistrableDomain: null, outTech: set, details: details);
        Assert.Contains("jQuery Migrate", set);
        Assert.Contains(details, d => d.Name == "jQuery Migrate" && d.Version == "3.3.2");
    }
}

