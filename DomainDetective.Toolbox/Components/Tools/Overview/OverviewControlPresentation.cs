using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Views;

namespace DomainDetective.Toolbox.Components.Tools.Overview;

internal static class OverviewControlPresentation
{
    public static IReadOnlyList<OverviewControlCardView> BuildAttentionCards(IReadOnlyList<AggregateCheckStatusInfo>? checks, int take = 8)
    {
        return BuildCards(checks, static check => check.State == AggregateCheckState.Fail || check.State == AggregateCheckState.Warning, take);
    }

    public static IReadOnlyList<OverviewControlCardView> BuildHealthyCards(IReadOnlyList<AggregateCheckStatusInfo>? checks, int take = 8)
    {
        return BuildCards(checks, static check => check.State == AggregateCheckState.Pass, take);
    }

    public static IReadOnlyList<OverviewControlCardView> BuildAllCards(IReadOnlyList<AggregateCheckStatusInfo>? checks, int take = 12)
    {
        return BuildCards(checks, static _ => true, take);
    }

    private static IReadOnlyList<OverviewControlCardView> BuildCards(IReadOnlyList<AggregateCheckStatusInfo>? checks, Func<AggregateCheckStatusInfo, bool> filter, int take)
    {
        if (checks == null || checks.Count == 0 || take <= 0)
        {
            return Array.Empty<OverviewControlCardView>();
        }

        return checks
            .Where(filter)
            .Take(take)
            .Select(BuildCard)
            .ToArray();
    }

    private static OverviewControlCardView BuildCard(AggregateCheckStatusInfo check)
    {
        var tags = new List<string> {
            GetStateLabel(check.State),
            GetAreaLabel(check.Key)
        };

        var samples = new List<string>();
        if (!string.IsNullOrWhiteSpace(check.Detail))
        {
            samples.Add(check.Detail.Trim());
        }

        return new OverviewControlCardView
        {
            Title = check.Label,
            ValueLabel = string.IsNullOrWhiteSpace(check.Value) ? GetStateLabel(check.State) : check.Value,
            Summary = BuildSummary(check),
            Tags = tags,
            Samples = samples,
            State = check.State,
            StateClass = BuildStateClass(check.State)
        };
    }

    private static string BuildSummary(AggregateCheckStatusInfo check)
    {
        var areaLabel = GetAreaLabel(check.Key);
        return check.State switch
        {
            AggregateCheckState.Fail => $"DD marked this {areaLabel.ToLowerInvariant()} control for remediation in the current overview run.",
            AggregateCheckState.Warning => $"DD found this {areaLabel.ToLowerInvariant()} control, but it still needs follow-up in the current overview run.",
            AggregateCheckState.Pass => $"DD marked this {areaLabel.ToLowerInvariant()} control as healthy in the current overview run.",
            _ => $"DD recorded this {areaLabel.ToLowerInvariant()} control as informational context for the current overview run."
        };
    }

    private static string GetStateLabel(AggregateCheckState state)
    {
        return state switch
        {
            AggregateCheckState.Pass => "Healthy",
            AggregateCheckState.Warning => "Needs follow-up",
            AggregateCheckState.Fail => "Needs remediation",
            _ => "Informational"
        };
    }

    private static string BuildStateClass(AggregateCheckState state)
    {
        return state switch
        {
            AggregateCheckState.Pass => "tool-callout-pass",
            AggregateCheckState.Warning => "tool-callout-warning",
            AggregateCheckState.Fail => "tool-callout-fail",
            _ => "tool-callout-info"
        };
    }

    private static string GetAreaLabel(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return "Posture";
        }

        switch (key.Trim().ToLowerInvariant())
        {
            case "spf":
            case "dkim":
            case "dmarc":
            case "bimi":
                return "Mail authentication";
            case "mx":
            case "mta-sts":
            case "tls-rpt":
                return "Mail transport";
            case "caa":
            case "dane":
            case "dnssec":
                return "Trust and DNS hardening";
            case "ns":
            case "soa":
                return "DNS infrastructure";
            case "http":
            case "cert":
            case "security-txt":
                return "Web posture";
            case "rdap":
                return "Registration";
            case "dnsbl":
            case "subdomains":
                return "Exposure";
            default:
                return "Posture";
        }
    }
}

public sealed class OverviewControlCardView
{
    public string Title { get; init; } = string.Empty;
    public string ValueLabel { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<string> Tags { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> Samples { get; init; } = Array.Empty<string>();
    public AggregateCheckState State { get; init; }
    public string StateClass { get; init; } = string.Empty;
}
