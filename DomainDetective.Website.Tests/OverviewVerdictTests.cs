using DomainDetective.Toolbox.Components.Shared;
using DomainDetective.Toolbox.Components.Tools.Overview;
using DomainDetective.Toolbox.Models;
using DomainDetective.Views;

namespace DomainDetective.Website.Tests;

public sealed class OverviewVerdictTests : BunitContext {
    [Fact]
    public void FailingControlsMakeTheVerdictActionNeededAndComeFirst() {
        var checks = new[] {
            Check("spf", "SPF", AggregateCheckState.Pass, "-all"),
            Check("mta-sts", "MTA-STS", AggregateCheckState.Warning, "Missing"),
            Check("dmarc", "DMARC", AggregateCheckState.Fail, "p=none"),
            Check("dnssec", "DNSSEC", AggregateCheckState.Pass, "Signed")
        };
        var advice = new[] {
            new RecommendationAdvice { Code = "Dmarc.Policy", Title = "Move DMARC to enforcement", Why = "Spoofed mail is delivered.", How = "Publish p=quarantine, then p=reject.", Domain = RecommendationDomain.Dmarc }
        };

        var view = OverviewVerdictPresentation.Build("contoso.com", checks, advice);

        Assert.Equal(OverviewVerdictTone.Action, view.Tone);
        Assert.Equal("Action needed", view.Headline);
        Assert.Equal((2, 1, 1), (view.Passed, view.Review, view.Failed));
        Assert.Equal("DMARC: p=none", view.FixFirst[0].Title);
        Assert.Equal("Publish p=quarantine, then p=reject.", view.FixFirst[0].How);
        Assert.Equal("dmarc", view.FixFirst[0].ToolSlug);
        Assert.Equal("fail", view.FixFirst[0].Severity);
        Assert.Equal("mta-sts", view.FixFirst[1].ToolSlug);
        Assert.Equal(2, view.Healthy.Count);
    }

    [Fact]
    public void AdviceAlreadyCoveredByAControlIsNotRepeated() {
        var checks = new[] { Check("dmarc", "DMARC", AggregateCheckState.Fail, "Missing") };
        var advice = new[] {
            new RecommendationAdvice { Title = "Publish DMARC", Domain = RecommendationDomain.Dmarc },
            new RecommendationAdvice { Title = "Add security headers", Domain = RecommendationDomain.Http }
        };

        var view = OverviewVerdictPresentation.Build("contoso.com", checks, advice);

        Assert.Equal(2, view.FixFirst.Count);
        Assert.Equal("Add security headers", view.FixFirst[1].Title);
        Assert.Equal("http-headers", view.FixFirst[1].ToolSlug);
    }

    [Fact]
    public void SpecificProtocolAdviceIsNotAttachedToTheWrongControl() {
        var checks = new[] {
            Check("mta-sts", "MTA-STS", AggregateCheckState.Warning, "Missing"),
            Check("cert", "Certificate", AggregateCheckState.Fail, "Expired")
        };
        var advice = new[] {
            new RecommendationAdvice { Code = "MtaSts.Missing", Title = "Publish an MTA-STS policy", How = "Publish _mta-sts TXT.", Domain = RecommendationDomain.Tls }
        };

        var view = OverviewVerdictPresentation.Build("contoso.com", checks, advice);

        Assert.Equal("cert-check", view.FixFirst[0].ToolSlug);
        Assert.Equal(string.Empty, view.FixFirst[0].How);
        Assert.Equal("mta-sts", view.FixFirst[1].ToolSlug);
        Assert.Equal("Publish _mta-sts TXT.", view.FixFirst[1].How);
    }

    [Fact]
    public void SectionsTheRunCouldNotAssessAreNamedInsteadOfCounted() {
        var view = OverviewVerdictPresentation.Build("contoso.com", new[] { Check("spf", "SPF", AggregateCheckState.Pass, "-all") }, null, notChecked: new[] { "Web and registration" });

        Assert.Equal(OverviewVerdictTone.Healthy, view.Tone);
        Assert.Equal(new[] { "Web and registration" }, view.NotChecked);
    }

    [Fact]
    public void CoreControlsOutrankOptionalOnesWithinTheSameSeverity() {
        var view = OverviewVerdictPresentation.Build("contoso.com", new[] {
            Check("bimi", "BIMI", AggregateCheckState.Fail, "Missing"),
            Check("tls-rpt", "TLS-RPT", AggregateCheckState.Fail, "Missing"),
            Check("dmarc", "DMARC", AggregateCheckState.Fail, "Missing"),
            Check("spf", "SPF", AggregateCheckState.Warning, "~all")
        }, null);

        Assert.Equal(new[] { "dmarc", "tls-rpt", "bimi" }, view.FixFirst.Select(item => item.ToolSlug));
    }

    [Fact]
    public void AllPassingControlsReadAsHealthyWithNothingToFix() {
        var view = OverviewVerdictPresentation.Build("contoso.com", new[] {
            Check("spf", "SPF", AggregateCheckState.Pass, "-all"),
            Check("dmarc", "DMARC", AggregateCheckState.Pass, "p=reject")
        }, null);

        Assert.Equal(OverviewVerdictTone.Healthy, view.Tone);
        Assert.Empty(view.FixFirst);
        Assert.Equal("All 2 assessed controls on contoso.com passed.", view.Summary);
    }

    [Fact]
    public void NoAssessedControlsGivesNoVerdict() {
        var view = OverviewVerdictPresentation.Build(null, new[] { Check("rdap", "RDAP", AggregateCheckState.Unknown, string.Empty) }, null);

        Assert.Equal(OverviewVerdictTone.Unknown, view.Tone);
        Assert.Equal(0, view.Assessed);
    }

    [Fact]
    public void VerdictLinksEachFixToItsToolForTheSameDomain() {
        var view = OverviewVerdictPresentation.Build("contoso.com", new[] { Check("cert", "Certificate", AggregateCheckState.Fail, "Expired") }, null);

        var cut = Render<OverviewVerdict>(parameters => parameters
            .Add(component => component.View, view)
            .Add(component => component.Domain, "contoso.com"));

        Assert.Contains("href=\"/tools/cert-check/?q=contoso.com\"", cut.Markup);
        Assert.Contains("Fix these first", cut.Markup);
    }

    [Fact]
    public void ChecklistShowsProblemsAndFoldsPassingChecks() {
        var cut = Render<ResultChecklist>(parameters => parameters
            .Add(component => component.Items, new[] {
                ResultCheck.Expect("Single SPF record", true, "Yes"),
                ResultCheck.Expect("No permanent error", false, "PermError"),
                ResultCheck.Expect("No ptr mechanism", true, "Yes"),
                ResultCheck.Fact("TXT TTL", "300s")
            }));

        var problems = cut.Find(".result-checklist-problems");
        Assert.Contains("No permanent error", problems.TextContent);
        Assert.DoesNotContain("Single SPF record", problems.TextContent);
        Assert.Contains("2 checks passed", cut.Find(".result-checklist-passed summary").TextContent);
        Assert.Contains("300s", cut.Find(".result-checklist-facts").TextContent);
    }

    [Fact]
    public void ChecklistSaysSoWhenNothingIsWrong() {
        var cut = Render<ResultChecklist>(parameters => parameters
            .Add(component => component.Items, new[] {
                ResultCheck.Expect("Record published", true, "Yes"),
                ResultCheck.Expect("Single record", true, "Yes")
            }));

        Assert.Contains("No problems in 2 checks", cut.Find(".result-checklist-clean").TextContent);
        Assert.Empty(cut.FindAll(".result-checklist-problems"));
    }

    private static AggregateCheckStatusInfo Check(string key, string label, AggregateCheckState state, string value) =>
        new() { Key = key, Label = label, State = state, Value = value };
}
