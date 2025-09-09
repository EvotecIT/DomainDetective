using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Providers.Email;

namespace DomainDetective;

public partial class DomainHealthCheck
{
    /// <summary>Best-effort detection of email providers (primary/gateways/outbound) based on MX, SPF, and DKIM signals.</summary>
    public ProviderMatch? EmailProviderMatch { get; private set; }

    private static IEnumerable<string> ParseMxHosts(IEnumerable<string> mxRecords)
    {
        foreach (var rec in mxRecords ?? Array.Empty<string>())
        {
            if (string.IsNullOrWhiteSpace(rec)) continue;
            // Expect format: "<pref> <host>" or just "host"; take last token as host
            var parts = rec.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            var host = parts.Length >= 2 ? parts[1] : parts[0];
            yield return host.Trim('.');
        }
    }

    private void ComputeEmailProviderMatch()
    {
        try
        {
            var mxHosts = ParseMxHosts(MXAnalysis?.MxRecords ?? new List<string>()).ToList();
            var spfTokens = new List<string>();
            if (SpfAnalysis != null)
            {
                spfTokens.AddRange(SpfAnalysis.IncludeRecords ?? new List<string>());
                spfTokens.AddRange(SpfAnalysis.ResolvedIncludeRecords ?? new List<string>());
                spfTokens.Add(SpfAnalysis.SpfRecord ?? string.Empty);
            }

            var dkimCnames = new List<string>();
            if (DKIMAnalysis?.AnalysisResults != null)
            {
                foreach (var kv in DKIMAnalysis.AnalysisResults)
                {
                    var cn = kv.Value?.CnameTarget;
                    if (!string.IsNullOrWhiteSpace(cn)) dkimCnames.Add(cn);
                }
            }

            EmailProviderMatch = EmailProviderDetector.Detect(mxHosts, spfTokens, dkimCnames);

            // Provider-aware DKIM selector count guidance
            try
            {
                var minSel = EmailProviderMatch?.Primary?.MinimumDkimSelectorsToPass ?? 0;
                if (minSel > 0 && DKIMAnalysis?.AnalysisResults != null)
                {
                    int validSel = DKIMAnalysis.AnalysisResults.Values.Count(v =>
                        v.DkimRecordExists && v.StartsCorrectly && v.PublicKeyExists && v.ValidPublicKey && v.ValidRsaKeyLength);
                    if (validSel >= minSel)
                    {
                        DKIMAnalysis.Assessments.Add(new Assessment
                        {
                            Code = DkimCodes.SelectorsMinimumMet,
                            Severity = AssessmentSeverity.Info,
                            Message = $"Provider requires at least {minSel} DKIM selector(s); {validSel} present.",
                            Target = DKIMAnalysis.Subject
                        });
                    }
                    else
                    {
                        DKIMAnalysis.Assessments.Add(new Assessment
                        {
                            Code = DkimCodes.SelectorsMinimumNotMet,
                            Severity = AssessmentSeverity.Warning,
                            Message = $"Detected provider recommends at least {minSel} DKIM selector(s); only {validSel} found.",
                            Target = DKIMAnalysis.Subject
                        });
                    }
                }
            } catch { }

            // Provider-aware SPF includes for outbound senders discovered via DKIM CNAME or other evidence
            try
            {
                var outbound = EmailProviderMatch?.OutboundSenders ?? new List<Providers.Email.IMailProvider>();
                if (outbound.Count > 0 && SpfAnalysis != null)
                {
                    var record = SpfAnalysis.SpfRecord ?? string.Empty;
                    foreach (var p in outbound)
                    {
                        var requirements = p.SpfRequiredTokens?.ToList() ?? new List<string>();
                        if (requirements.Count == 0) continue;
                        bool present = requirements.All(req => record.IndexOf(req, StringComparison.OrdinalIgnoreCase) >= 0);
                        SpfAnalysis.Assessments.Add(new Assessment
                        {
                            Code = present ? SpfCodes.ProviderIncludePresent : SpfCodes.ProviderIncludeMissing,
                            Severity = present ? AssessmentSeverity.Info : AssessmentSeverity.Warning,
                            Message = present
                                ? $"SPF include for {p.DisplayName} present."
                                : $"SPF include for {p.DisplayName} missing.",
                            Target = SpfAnalysis.Subject
                        });
                    }
                }
            } catch { }
        }
        catch { EmailProviderMatch = null; }
    }
}
