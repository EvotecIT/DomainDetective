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

            // Provider-aware MTA-STS/TLSRPT guidance when a primary or gateway was inferred
            try
            {
                bool hasProvider = (EmailProviderMatch?.Primary != null) || (EmailProviderMatch?.Gateways?.Count > 0);
                if (hasProvider)
                {
                    // Encourage DMARC enforcement for domains with outbound providers and weak/no enforcement
                    try
                    {
                        var outbound = EmailProviderMatch?.OutboundSenders ?? new List<Providers.Email.IMailProvider>();
                        if (outbound.Count > 0 && DmarcAnalysis != null)
                        {
                            var policy = (DmarcAnalysis.Policy ?? string.Empty).Trim().ToLowerInvariant();
                            if (string.IsNullOrWhiteSpace(policy) || policy == "none")
                            {
                                var prov = EmailProviderMatch?.Primary ?? outbound.FirstOrDefault();
                                string? help = null;
                                try { var meta = prov?.Docs?.Get("DMARC"); if (!string.IsNullOrWhiteSpace(meta?.Url)) help = meta.Url; } catch { }
                                var extra = string.IsNullOrWhiteSpace(help) ? string.Empty : $" See: {help}";
                                DmarcAnalysis.Assessments.Add(new Assessment
                                {
                                    Code = DmarcCodes.ProviderEnforcementRecommended,
                                    Severity = AssessmentSeverity.Warning,
                                    Message = $"Detected outbound provider; recommend moving DMARC to quarantine/reject after monitoring.{extra}",
                                    Target = DmarcAnalysis.Subject
                                });
                            }
                        }
                    } catch { }

                    if (MTASTSAnalysis != null && !MTASTSAnalysis.PolicyValid)
                    {
                        MTASTSAnalysis.Assessments.Add(new Assessment
                        {
                            Code = MtaStsCodes.ProviderRecommended,
                            Severity = AssessmentSeverity.Warning,
                            Message = "Enable MTA-STS ('enforce' when ready) for the detected mail provider(s).",
                            Target = MTASTSAnalysis.Domain
                        });
                    }
                    if (TLSRPTAnalysis != null && !TLSRPTAnalysis.PolicyValid)
                    {
                        TLSRPTAnalysis.Assessments.Add(new Assessment
                        {
                            Code = TlsRptCodes.ProviderRecommended,
                            Severity = AssessmentSeverity.Warning,
                            Message = "Publish TLSRPT to receive TLS failure reports for the detected provider(s).",
                            Target = TLSRPTAnalysis.Subject
                        });
                    }

                    // DMARC subdomain policy hint: suggest sp= when providers present and sp is not specified explicitly
                    try
                    {
                        if (DmarcAnalysis != null && DmarcAnalysis.DmarcRecordExists)
                        {
                            // Heuristic: If outbound or gateways present and 'sp' not present, suggest adding sp=
                            bool hasOutboundOrGateway = (EmailProviderMatch?.OutboundSenders?.Count ?? 0) > 0 || (EmailProviderMatch?.Gateways?.Count ?? 0) > 0;
                            bool hasSpExplicit = !string.IsNullOrWhiteSpace(DmarcAnalysis.SubPolicyShort);
                            if (hasOutboundOrGateway && !hasSpExplicit)
                            {
                                var providerName = EmailProviderMatch?.Primary?.DisplayName ?? (EmailProviderMatch?.Gateways?.FirstOrDefault()?.DisplayName ?? "provider");
                                var rec = EmailProviderMatch?.Primary?.SubdomainPolicyRecommendation ?? Providers.Email.DmarcSubdomainPolicyRecommendation.MatchParent;
                                string hint = rec switch
                                {
                                    Providers.Email.DmarcSubdomainPolicyRecommendation.Quarantine => "Use sp=quarantine.",
                                    Providers.Email.DmarcSubdomainPolicyRecommendation.Reject => "Use sp=reject.",
                                    _ => "Use sp= to match the organizational policy (quarantine/reject)."
                                };
                                string? help = null;
                                try { var meta = EmailProviderMatch?.Primary?.Docs?.Get("DMARC"); if (!string.IsNullOrWhiteSpace(meta?.Url)) help = meta.Url; } catch { }
                                var extra = string.IsNullOrWhiteSpace(help) ? string.Empty : $" See: {help}";
                                DmarcAnalysis.Assessments.Add(new Assessment
                                {
                                    Code = DmarcCodes.SubdomainPolicyRecommended,
                                    Severity = AssessmentSeverity.Info,
                                    Message = $"Consider adding sp= to DMARC to enforce policy for subdomains used with {providerName}. {hint}{extra}",
                                    Target = DmarcAnalysis.Subject
                                });
                            }
                        }
                    } catch { }
                }
            } catch { }
        }
        catch { EmailProviderMatch = null; }
    }
}
