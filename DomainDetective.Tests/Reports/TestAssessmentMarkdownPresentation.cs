using AngleSharp.Html.Parser;
using DomainDetective.Reports;
using DomainDetective.Reports.Markdown;
using OfficeIMO.Markdown;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Tests.Reports;

public class TestAssessmentMarkdownPresentation {
    [Fact]
    public void SharedActionsGroupDomainsAndOrderSeverityBeforeReach() {
        var report = AssessmentExportFixture.Create(3);
        var spf = report.Domains[0].Checks.Single(check => check.Key == "spf");
        spf.Outcome = CheckOutcome.Error;
        spf.Findings.Add(new CheckFinding { Severity = AssessmentSeverity.Error, Message = "SPF action" });
        var otherSpf = report.Domains[1].Checks.Single(check => check.Key == "spf");
        otherSpf.Outcome = CheckOutcome.Warning;
        otherSpf.Findings.Add(new CheckFinding { Severity = AssessmentSeverity.Warning, Message = "A different SPF action" });
        foreach (var domain in report.Domains.Take(2)) {
            var dnsbl = domain.Checks.Single(check => check.Key == "dnsbl");
            dnsbl.Outcome = CheckOutcome.Warning;
            dnsbl.Findings.Add(new CheckFinding { Severity = AssessmentSeverity.Warning, Message = "DNSBL action" });
        }
        string[] lines = ActionLines(AssessmentMarkdownReport.Render(report));
        Assert.Equal(5, lines.Length);
        Assert.StartsWith("1. **DMARC** (All 3 domains,", lines[0]);
        Assert.StartsWith("2. **SPF** (example01.example.test,", lines[1]);
        Assert.StartsWith("3. **Certificate** (All 3 domains,", lines[2]);
        Assert.StartsWith("4. **DNSBL** (2 domains: example01.example.test, example02.example.test,", lines[3]);
        Assert.StartsWith("5. **SPF** (example02.example.test,", lines[4]);
        Assert.EndsWith("A different SPF action", lines[4]);
    }

    [Fact]
    public void PriorityActionsHaveExactlyOneLineEachWithLowercaseOutcomes() {
        string markdown = AssessmentMarkdownReport.Render(AssessmentExportFixture.Create());
        Assert.Equal(new[] {
            "1. **DMARC** (example.test, Mail, error): The published policy permits spoofed mail.",
            "2. **Certificate** (example.test, Web, warning): The certificate expires in 12 days."
        }, ActionLines(markdown));
    }

    [Theory]
    [InlineData(1, "Mail · 2 findings")]
    [InlineData(3, "Mail · 4 findings")]
    public void PriorityActionRetainsSharedSourceWhenAdditionalFindingsExist(int more, string source) {
        var report = AssessmentExportFixture.Create();
        var check = report.Domains[0].Checks[0];
        check.WarningCount = more;
        for (int index = 0; index < more; index++) {
            check.Findings.Add(new CheckFinding { Severity = AssessmentSeverity.Warning, Message = "Another policy finding " + index + "." });
        }
        Assert.Equal(source, Wording.DoFirstSource(check));
        string[] lines = ActionLines(AssessmentMarkdownReport.Render(report));
        Assert.Equal(2, lines.Length);
        Assert.Equal("1. **DMARC** (example.test, " + source + ", error): The published policy permits spoofed mail.", lines[0]);
    }

    [Fact]
    public void InlineContentUsesLiteralParenthesesSingleSpacesAndMarkdownEscapes() {
        const string raw = "Review (owner)  A & B\r\n\t<script>alert('x')</script> &lt; &#60; &#x3c; [link](https://example.test) *bold* _value_ `code` | \\ $5 ^2!";
        const string expected = @"Review (owner) A & B \<script\>alert('x')\</script\> \&lt; \&\#60; \&\#x3c; \[link\](https://example.test) \*bold\* \_value\_ \`code\` \| \\ $5 ^2!";
        var report = AssessmentExportFixture.Create();
        var check = report.Domains[0].Checks[0];
        check.Findings[0].Message = raw;
        check.Description = raw;
        check.Positives.Add(raw);
        check.Evidence.Add(new CheckEvidence { Title = "Inline safety", Kind = CheckEvidenceKind.Table, Columns = { "Value" }, Rows = { new List<string> { raw } } });

        string markdown = AssessmentMarkdownReport.Render(report);
        Assert.Equal("1. **DMARC** (example.test, Mail, error): " + expected, ActionLines(markdown)[0]);
        Assert.Contains("\n" + expected + "\n", markdown.Replace("\r\n", "\n"));
        Assert.Contains("- " + expected, markdown);
        Assert.Contains("| " + expected + " |", markdown);
        Assert.DoesNotContain("\\(", markdown);
        Assert.DoesNotContain("&#40;", markdown);
        Assert.DoesNotContain("&#41;", markdown);
        using var markdownDocument = MarkdownDocument.Parse(markdown);
        string html = markdownDocument.ToHtml(new MarkdownHtmlExportOptions { Kind = MarkdownHtmlKind.Fragment });
        var document = new HtmlParser().ParseDocument(html);
        Assert.Empty(document.QuerySelectorAll("script, img, a[href='https://example.test']"));
        Assert.Contains("Review (owner) A & B <script>alert('x')</script> &lt; &#60; &#x3c; [link](https://example.test) *bold* _value_ `code` | \\ $5 ^2!", document.Body!.TextContent);
    }

    [Theory]
    [InlineData("# Heading", @"\# Heading")]
    [InlineData("- List item", @"\- List item")]
    [InlineData("+ List item", @"\+ List item")]
    [InlineData("1. List item", @"1\. List item")]
    [InlineData("  1. List item", @"1\. List item")]
    [InlineData("1) List item", @"1\) List item")]
    [InlineData("[Policy]: none", @"\[Policy\]: none")]
    public void ProseCannotIntroduceMarkdownBlocks(string description, string expected) {
        var report = AssessmentExportFixture.Create();
        report.Domains[0].Checks[0].Description = description;
        string markdown = AssessmentMarkdownReport.Render(report).Replace("\r\n", "\n");
        Assert.Contains("\n" + expected + "\n", markdown);
    }

    [Fact]
    public void HeadingAndBoldTitleKeepHtmlAndEntitiesLiteral() {
        const string title = "Mail (owner) <img src=x onerror=alert(1)> &amp;";
        const string escaped = @"Mail (owner) \<img src=x onerror=alert(1)\> \&amp;";
        var report = AssessmentExportFixture.Create();
        report.Domains[0].Checks[0].Title = title;
        string markdown = AssessmentMarkdownReport.Render(report);
        Assert.Equal("1. **" + escaped + "** (example.test, Mail, error): The published policy permits spoofed mail.", ActionLines(markdown)[0]);
        Assert.Contains("#### " + escaped + " · Error", markdown);
        using var markdownDocument = MarkdownDocument.Parse(markdown);
        string html = markdownDocument.ToHtml(new MarkdownHtmlExportOptions { Kind = MarkdownHtmlKind.Fragment });
        var document = new HtmlParser().ParseDocument(html);
        Assert.Empty(document.QuerySelectorAll("img"));
        Assert.Contains(title, document.Body!.TextContent);
    }

    private static string[] ActionLines(string markdown) {
        int start = markdown.IndexOf("## Do these first", StringComparison.Ordinal) + "## Do these first".Length;
        int end = markdown.IndexOf("## Area by area", start, StringComparison.Ordinal);
        return markdown.Substring(start, end - start).Replace("\r\n", "\n")
            .Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
    }
}
