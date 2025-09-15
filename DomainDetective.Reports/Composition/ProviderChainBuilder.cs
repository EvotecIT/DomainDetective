using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Reports;

/// <summary>
/// Builds a simple provider chain (Primary, Gateways, Outbound) from mixed views.
/// Keep this logic in one place so all renderers print the same line.
/// </summary>
public static class ProviderChainBuilder
{
    public sealed class ProviderChain
    {
        public string? Primary { get; }
        public List<string> Gateways { get; }
        public List<string> Outbound { get; }
        public ProviderChain(string? primary, List<string> gateways, List<string> outbound)
        { Primary = primary; Gateways = gateways; Outbound = outbound; }
    }

    public static ProviderChain Build(DomainDetective.Views.MxInfo? mx, DomainDetective.Views.SpfRecordInfo? spf)
    {
        var primary = mx?.ProviderPrimary;
        var gateways = mx?.ProviderGateways != null
            ? new List<string>(mx.ProviderGateways.Distinct(StringComparer.OrdinalIgnoreCase))
            : new List<string>();

        var outbound = new List<string>();
        try
        {
            var names = (spf?.ProviderHelp ?? new List<DomainDetective.Views.ProviderHelpLinks>())
                .Select(p => p?.ProviderName)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            foreach (var n in names)
            {
                if (string.IsNullOrWhiteSpace(n)) continue;
                if (!string.IsNullOrWhiteSpace(primary) && string.Equals(n, primary, StringComparison.OrdinalIgnoreCase)) continue;
                if (gateways.Contains(n, StringComparer.OrdinalIgnoreCase)) continue;
                outbound.Add(n);
            }
        }
        catch { }

        return new ProviderChain(primary, gateways, outbound);
    }
}
