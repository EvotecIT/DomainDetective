using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.CLI.Wizard;

public sealed partial class DomainWizard {
    /// <summary>Builds presentation groups and one complete execution plan. Explicit selection takes precedence over presets.</summary>
    internal static (List<(string Title, HealthCheckType[] Types, bool Enabled)> Stages, HealthCheckType[] Checks) BuildPlan(WizardOptions options) {
        bool explicitSelection = options.Checks != null && options.Checks.Length > 0;
        HealthCheckType[] dnsChecks;
        List<HealthCheckType> mailChecksList;
        HealthCheckType[] webChecks;
        HealthCheckType[] repChecks;

        if (options.Checks != null && options.Checks.Length > 0)
        {
            var set = new HashSet<HealthCheckType>(options.Checks);
            dnsChecks = new[] { HealthCheckType.NS, HealthCheckType.SOA, HealthCheckType.DNSSEC, HealthCheckType.WILDCARDDNS, HealthCheckType.OPENRESOLVER, HealthCheckType.ZONETRANSFER, HealthCheckType.TTL }.Where(set.Contains).ToArray();
            var mailBase = new[] { HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.BIMI, HealthCheckType.MTASTS, HealthCheckType.TLSRPT };
            mailChecksList = mailBase.Where(set.Contains).ToList();
            // If user selected any active probes include them; otherwise honor ActiveMailProbes flag
            var probes = new[] { HealthCheckType.STARTTLS, HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS, HealthCheckType.SMTPBANNER, HealthCheckType.SMTPAUTH, HealthCheckType.OPENRELAY };
            var selectedProbes = probes.Where(set.Contains).ToArray();
            if (selectedProbes.Length > 0)
                mailChecksList.AddRange(selectedProbes);
            else if (options.ActiveMailProbes)
                mailChecksList.AddRange(probes);
            webChecks = new[] { HealthCheckType.HTTP, HealthCheckType.CERT, HealthCheckType.DANE }.Where(set.Contains).ToArray();
            repChecks = new[] { HealthCheckType.DNSBL, HealthCheckType.RDAP, HealthCheckType.RPKI }.Where(set.Contains).ToArray();
        }
        else
        {
            dnsChecks = new[] { HealthCheckType.NS, HealthCheckType.SOA, HealthCheckType.DNSSEC, HealthCheckType.WILDCARDDNS, HealthCheckType.OPENRESOLVER, HealthCheckType.ZONETRANSFER, HealthCheckType.TTL };
            mailChecksList = new List<HealthCheckType> { HealthCheckType.MX, HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.BIMI, HealthCheckType.MTASTS, HealthCheckType.TLSRPT };
            if (options.ActiveMailProbes)
            {
                mailChecksList.AddRange(new[] { HealthCheckType.STARTTLS, HealthCheckType.SMTPTLS, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS, HealthCheckType.SMTPBANNER, HealthCheckType.SMTPAUTH, HealthCheckType.OPENRELAY });
            }
            webChecks = new[] { HealthCheckType.HTTP, HealthCheckType.CERT, HealthCheckType.DANE };
            repChecks = new[] { HealthCheckType.DNSBL, HealthCheckType.RDAP, HealthCheckType.RPKI };
        }

        var stages = new List<(string Title, HealthCheckType[] Types, bool Enabled)>
        {
            ("🧭 DNS", dnsChecks, dnsChecks.Length > 0),
            ("📧 Mail", mailChecksList.ToArray(), mailChecksList.Count > 0),
            ("🌐 Web", webChecks, webChecks.Length > 0 && (explicitSelection || options.Mode != ScanMode.Quick)),
            ("🛡 Reputation", repChecks, repChecks.Length > 0 && (explicitSelection || options.Mode == ScanMode.Full))
        };

        if (explicitSelection) {
            var grouped = new HashSet<HealthCheckType>(stages.SelectMany(stage => stage.Types));
            var other = options.Checks!.Where(check => !grouped.Contains(check)).Distinct().ToArray();
            stages.Add(("Other checks", other, other.Length > 0));
        }
        var checks = stages.Where(stage => stage.Enabled).SelectMany(stage => stage.Types)
            .Concat(!explicitSelection && stages[3].Enabled ? new[] { HealthCheckType.WHOIS } : Array.Empty<HealthCheckType>())
            .Distinct().ToArray();
        return (stages, checks);
    }
}
