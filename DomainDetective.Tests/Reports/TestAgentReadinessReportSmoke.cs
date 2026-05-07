using System;
using System.Collections.Generic;
using System.IO;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests.Reports;

public class TestAgentReadinessReportSmoke
{
    [Fact]
    public void AgentReadiness_Appears_In_Html_And_Markdown_Composition()
    {
        var domain = "example.org";
        var view = new AgentReadinessInfo
        {
            Subject = domain,
            Status = "Warning",
            Score = 72.5,
            RobotsPresent = true,
            SitemapCount = 1,
            LlmsTxtPresent = true,
            MarkdownDirect = false,
            MarkdownAlternateUrl = "https://example.org/index.md",
            ContentSignals = new[]
            {
                new ContentSignalPolicy
                {
                    Source = "robots.txt",
                    Search = "yes",
                    AiInput = "yes",
                    AiTrain = "no",
                    RawValue = "search=yes, ai-input=yes, ai-train=no"
                }
            },
            LinkRelations = new[]
            {
                new AgentReadinessLinkRelation
                {
                    Relation = "api-catalog",
                    Target = "https://example.org/.well-known/api-catalog",
                    Type = "application/linkset+json",
                    SourceUrl = "https://example.org/"
                }
            },
            EndpointProbes = new[]
            {
                new AgentReadinessEndpointProbe
                {
                    Kind = "api-catalog",
                    Url = "https://example.org/.well-known/api-catalog",
                    StatusCode = 200,
                    ContentType = "application/linkset+json",
                    Present = true,
                    ValidJson = true,
                    ShapeValid = true,
                    Shape = "RFC9727 linkset",
                    DiscoverySource = "well-known"
                }
            },
            CategoryScores = new[]
            {
                new AgentReadinessCategoryScore
                {
                    Category = "Discoverability",
                    Score = 20,
                    MaxScore = 25,
                    WeightedScore = 20,
                    Weight = 25,
                    Passed = 4,
                    Warnings = 1,
                    Failed = 0
                }
            },
            Checks = new[]
            {
                new AgentReadinessCheck
                {
                    Id = "llms-txt",
                    Category = "Discoverability",
                    Name = "llms.txt",
                    Status = AgentReadinessCheckStatus.Pass,
                    Score = 5,
                    MaxScore = 5,
                    Evidence = "llms.txt found.",
                    Code = AgentReadinessCodes.LlmsTxtPresent
                }
            },
            Assessments = new[]
            {
                new Assessment
                {
                    Severity = AssessmentSeverity.Warning,
                    Category = "AgentReadiness",
                    Target = domain,
                    Code = AgentReadinessCodes.SecurityHeadersWeak,
                    Message = "Trust headers: only partial trust headers found."
                }
            }
        };

        var items = new List<object> { view };
        var tmpHtml = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        var tmpMd = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".md");

        HtmlCompositionReport.Generate(tmpHtml, items, ReportScope.Detailed);
        MarkdownCompositionReport.Generate(tmpMd, items, ReportScope.Detailed);

        var html = File.ReadAllText(tmpHtml);
        var markdown = File.ReadAllText(tmpMd);

        Assert.Contains("Agent Readiness", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("72.5", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("api-catalog", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Agent Readiness", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("72.5", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("llms.txt", markdown, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Sitemap_Appears_In_Html_And_Markdown_Composition()
    {
        var domain = "example.org";
        var view = new SitemapInfo
        {
            Subject = domain,
            Status = "Warning",
            WarningCount = 2,
            ErrorCount = 1,
            DocumentCount = 1,
            UrlCount = 3,
            ProbeCount = 3,
            RedirectLoopCount = 1,
            ClientErrorCount = 1,
            Documents = new[]
            {
                new SitemapDocumentInfo
                {
                    Url = "https://example.org/sitemap.xml",
                    StatusCode = 200,
                    ContentType = "application/xml",
                    Present = true,
                    XmlValid = true,
                    NamespaceValid = true,
                    Kind = "UrlSet",
                    UrlCount = 3
                }
            },
            ProblemUrls = new[]
            {
                new SitemapUrlProbeInfo
                {
                    Url = "https://example.org/loop/",
                    FinalUrl = "https://example.org/loop/",
                    StatusCode = 301,
                    WasRedirected = true,
                    RedirectLoop = true,
                    Error = "Redirect loop detected."
                }
            },
            Assessments = new[]
            {
                new Assessment
                {
                    Severity = AssessmentSeverity.Error,
                    Category = "Sitemap",
                    Target = "https://example.org/loop/",
                    Code = SitemapCodes.UrlRedirectLoop,
                    Message = "Sitemap URL has a redirect loop."
                }
            }
        };

        var items = new List<object> { view };
        var tmpHtml = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".html");
        var tmpMd = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".md");

        HtmlCompositionReport.Generate(tmpHtml, items, ReportScope.Detailed);
        MarkdownCompositionReport.Generate(tmpMd, items, ReportScope.Detailed);

        var html = File.ReadAllText(tmpHtml);
        var markdown = File.ReadAllText(tmpMd);

        Assert.Contains("Sitemap", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Problem URL", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://example.org/loop/", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Sitemap", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Redirect loop", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://example.org/sitemap.xml", markdown, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Composition_Preserves_Url_Specific_Web_Discovery_Subjects()
    {
        var agentHome = new AgentReadinessInfo
        {
            Subject = "https://example.org/"
        };
        var agentDocs = new AgentReadinessInfo
        {
            Subject = "https://example.org/docs/"
        };
        var sitemapHome = new SitemapInfo
        {
            Subject = "https://example.org/sitemap.xml"
        };
        var sitemapDocs = new SitemapInfo
        {
            Subject = "https://example.org/docs/sitemap.xml"
        };

        var map = CompositionBuilder.GroupBySubject(new object[] { agentHome, agentDocs, sitemapHome, sitemapDocs });

        Assert.Equal(4, map.Count);
        Assert.Same(agentHome, map["https://example.org/"].AgentReadiness);
        Assert.Same(agentDocs, map["https://example.org/docs/"].AgentReadiness);
        Assert.Same(sitemapHome, map["https://example.org/sitemap.xml"].Sitemap);
        Assert.Same(sitemapDocs, map["https://example.org/docs/sitemap.xml"].Sitemap);
    }
}
