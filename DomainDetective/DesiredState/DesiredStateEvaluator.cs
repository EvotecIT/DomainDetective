using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    public static DesiredStateAnalysis Evaluate(
        string domain,
        DomainHealthCheck health,
        DesiredStateProfile profile,
        MailDomainClassificationCategory? classification = null,
        DesiredStateEvaluationOptions? options = null) {
        if (domain == null) {
            throw new ArgumentNullException(nameof(domain));
        }
        if (domain.Trim().Length == 0) {
            throw new ArgumentException("Domain cannot be empty or whitespace.", nameof(domain));
        }
        if (health == null) {
            throw new ArgumentNullException(nameof(health));
        }
        if (profile == null) {
            throw new ArgumentNullException(nameof(profile));
        }

        profile.Normalize();

        var result = new DesiredStateAnalysis {
            Subject = domain,
            MailClassification = classification
        };

        try {
            ApplyAssessmentPolicy(health, profile.AssessmentPolicy);
        } catch (Exception ex) {
            // Policy application should not prevent desired state evaluation.  
            TraceException("ApplyAssessmentPolicy(health, policy)", ex, options);
            if (options?.ThrowOnError == true) {
                throw;
            }
        }

        try {
            AppendHealthAssessments(health, result);
        } catch (Exception ex) {
            // Collection should not prevent desired state evaluation.
            TraceException("AppendHealthAssessments(health, result)", ex, options);
            if (options?.ThrowOnError == true) {
                throw;
            }
        }

        EvaluateDmarc(domain, health.DmarcAnalysis, profile.Dmarc, result);
        EvaluateSpf(domain, health.SpfAnalysis, profile.Spf, result);
        EvaluateDkim(domain, health.DKIMAnalysis, profile.Dkim, result);
        EvaluateMtasts(domain, health.MTASTSAnalysis, profile.Mtasts, result);
        EvaluateTlsRpt(domain, health.TLSRPTAnalysis, profile.TlsRpt, result);
        EvaluateBimi(domain, health.BimiAnalysis, profile.Bimi, result);
        EvaluateMx(domain, health.MXAnalysis, profile.Mx, result);
        EvaluateStartTls(domain, health.StartTlsAnalysis, profile.StartTls, result);
        EvaluateSmtpTls(domain, health.SmtpTlsAnalysis, profile.SmtpTls, result);
        EvaluateImapTls(domain, health.ImapTlsAnalysis, profile.ImapTls, result);
        EvaluatePop3Tls(domain, health.Pop3TlsAnalysis, profile.Pop3Tls, result);
        EvaluateSmtpBanner(domain, health.SmtpBannerAnalysis, profile.SmtpBanner, result);
        EvaluateSmtpAuth(domain, health.SmtpAuthAnalysis, profile.SmtpAuth, result);
        EvaluateOpenRelay(domain, health.OpenRelayAnalysis, profile.OpenRelay, result);
        EvaluateMailLatency(domain, health.MailLatencyAnalysis, profile.MailLatency, result);
        EvaluateOpenResolver(domain, health.OpenResolverAnalysis, profile.OpenResolver, result);
        EvaluateReverseDns(domain, health.ReverseDnsAnalysis, profile.ReverseDns, result);
        EvaluateFcrDns(domain, health.FcrDnsAnalysis, profile.FcrDns, result);
        EvaluateNs(domain, health.NSAnalysis, profile.Ns, result);
        EvaluateDanglingCname(domain, health.DanglingCnameAnalysis, profile.DanglingCname, result);
        EvaluateCaa(domain, health.CAAAnalysis, profile.Caa, result);
        EvaluateDnssec(domain, health.DnsSecAnalysis, profile.DnsSec, result);
        EvaluateSoa(domain, health.SOAAnalysis, profile.Soa, result);
        EvaluateDane(domain, health.DaneAnalysis, profile.Dane, result);
        EvaluateDnsbl(domain, health.DNSBLAnalysis, profile.Dnsbl, result);
        EvaluateDnsHealth(domain, health.DnsHealthAnalysis, profile.DnsHealth, result);
        EvaluateApexAddress(domain, health.ApexAddressAnalysis, profile.ApexAddress, result);
        EvaluateRpki(domain, health.RpkiAnalysis, profile.Rpki, result);
        EvaluateEdnsSupport(domain, health.EdnsSupportAnalysis, profile.EdnsSupport, result);
        EvaluateDnsOverTls(domain, health.DnsOverTlsAnalysis, profile.DnsOverTls, result);
        EvaluateFlatteningService(domain, health.FlatteningServiceAnalysis, profile.FlatteningService, result);
        EvaluateDelegation(domain, health.NSAnalysis, profile.Delegation, result);
        EvaluateZoneTransfer(domain, health.ZoneTransferAnalysis, profile.ZoneTransfer, result);
        EvaluateWildcardDns(domain, health.WildcardDnsAnalysis, profile.WildcardDns, result);
        EvaluateTtl(domain, health.DnsTtlAnalysis, profile.Ttl, result);
        EvaluateAutodiscover(domain, health.AutodiscoverAnalysis, profile.Autodiscover, result);
        EvaluateSecurityTxt(domain, health.SecurityTXTAnalysis, profile.SecurityTxt, result);
        EvaluateRobots(domain, health.RobotsTxtAnalysis, profile.Robots, result);

        // Apply policy so users can suppress/override DesiredState.* codes as well.
        try {
            ApplyAssessmentPolicy(result, profile.AssessmentPolicy);
        } catch (Exception ex) {
            TraceException("ApplyAssessmentPolicy(result, policy)", ex, options);
            if (options?.ThrowOnError == true) {
                throw;
            }
        }

        var hasProblems = result.Assessments.Any(a =>
            a.Severity != AssessmentSeverity.Info &&
            string.Equals(a.Category, "DesiredState", StringComparison.OrdinalIgnoreCase));
        result.Conforms = !hasProblems;
        if (result.Conforms) {
            result.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Info,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.Conforms,
                Message = "Domain conforms to the desired state baseline."
            });
            try {
                ApplyAssessmentPolicy(result, profile.AssessmentPolicy);
            } catch (Exception ex) {
                TraceException("ApplyAssessmentPolicy(result, policy) after Conforms", ex, options);
                if (options?.ThrowOnError == true) {
                    throw;
                }
            }
        }
        return result;
    }

    public static void ApplyAssessmentPolicy(DomainHealthCheck health, DesiredStateAssessmentPolicy? policy) {
        if (health == null || policy == null) return;

        var suppress = new HashSet<string>(policy.SuppressCodes ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var overrides = policy.SeverityOverrides ?? new Dictionary<string, AssessmentSeverity>(StringComparer.OrdinalIgnoreCase);
        foreach (var has in health.GetAssessmentProviders()) {
            if (has.Assessments != null) {
                ApplyAssessmentPolicy(has, suppress, overrides);
            }
        }
    }

    private static void AppendHealthAssessments(DomainHealthCheck health, DesiredStateAnalysis sink) {
        if (health == null) return;
        if (sink == null) return;
        foreach (var a in health.GetAllAssessments()) {
            if (a == null) continue;
            sink.Assessments.Add(CloneAssessment(a));
        }
    }

    private static void TraceException(string context, Exception ex, DesiredStateEvaluationOptions? options) {
        if (ex == null) {
            return;
        }
        if (options?.LogExceptionsAsErrors == true) {
            Trace.TraceError("DesiredStateEvaluator: {0}: {1}", context, ex);
        } else {
            Trace.TraceWarning("DesiredStateEvaluator: {0}: {1}", context, ex);
        }
    }

    private static Assessment CloneAssessment(Assessment a) {
        return new Assessment {
            Severity = a.Severity,
            Message = a.Message,
            Code = a.Code,
            Category = a.Category,
            Source = a.Source,
            Target = a.Target,
            Timestamp = a.Timestamp,
            Metadata = a.Metadata != null
                ? new Dictionary<string, string>(a.Metadata)
                : new Dictionary<string, string>()
        };
    }

    public static void ApplyAssessmentPolicy(IHasAssessments hasAssessments, DesiredStateAssessmentPolicy? policy) {
        if (hasAssessments == null || policy == null) return;
        var suppress = new HashSet<string>(policy.SuppressCodes ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var overrides = policy.SeverityOverrides ?? new Dictionary<string, AssessmentSeverity>(StringComparer.OrdinalIgnoreCase);
        ApplyAssessmentPolicy(hasAssessments, suppress, overrides);
    }

    private static void ApplyAssessmentPolicy(IHasAssessments hasAssessments, HashSet<string> suppress, Dictionary<string, AssessmentSeverity> overrides) {
        var list = hasAssessments.Assessments;
        if (list == null || list.Count == 0) return;

        if (suppress.Count > 0) {
            for (var i = list.Count - 1; i >= 0; i--) {
                if (list[i]?.Code is string code && !string.IsNullOrWhiteSpace(code) && suppress.Contains(code)) {
                    list.RemoveAt(i);
                }
            }
        }

        if (overrides.Count > 0) {
            foreach (var a in list) {
                if (a == null) continue;
                if (a.Code is string code && !string.IsNullOrWhiteSpace(code) && overrides.TryGetValue(code, out var sev)) {
                    a.Severity = sev;
                }
            }
        }
    }
}
