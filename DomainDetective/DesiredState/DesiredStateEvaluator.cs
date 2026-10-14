using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state evaluator functionality.</summary>
public static partial class DesiredStateEvaluator {
    /// <summary>Executes the evaluate operation.</summary>
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

        bool CanEvaluate(HealthCheckType check) {
            var failure = health.GetCheckFailure(check);
            if (failure == null) { return true; }
            result.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error, Category = "DesiredState", Target = domain,
                Code = "DesiredState.Check.QueryFailed", Message = $"Desired state for {check} could not be verified: {failure.Message}"
            });
            return false;
        }

        if (profile.Dmarc == null || profile.Dmarc.Enabled == false || CanEvaluate(HealthCheckType.DMARC)) { EvaluateDmarc(domain, health.DmarcAnalysis, profile.Dmarc, result); }
        if (profile.Spf == null || profile.Spf.Enabled == false || CanEvaluate(HealthCheckType.SPF)) { EvaluateSpf(domain, health.SpfAnalysis, profile.Spf, result); }
        if (profile.Dkim == null || profile.Dkim.Enabled == false || CanEvaluate(HealthCheckType.DKIM)) { EvaluateDkim(domain, health.DKIMAnalysis, profile.Dkim, result); }
        if (profile.Mtasts == null || profile.Mtasts.Enabled == false || CanEvaluate(HealthCheckType.MTASTS)) { EvaluateMtasts(domain, health.MTASTSAnalysis, profile.Mtasts, result); }
        if (profile.TlsRpt == null || profile.TlsRpt.Enabled == false || CanEvaluate(HealthCheckType.TLSRPT)) { EvaluateTlsRpt(domain, health.TLSRPTAnalysis, profile.TlsRpt, result); }
        if (profile.Bimi == null || profile.Bimi.Enabled == false || CanEvaluate(HealthCheckType.BIMI)) { EvaluateBimi(domain, health.BimiAnalysis, profile.Bimi, result); }
        if (profile.Mx == null || profile.Mx.Enabled == false || CanEvaluate(HealthCheckType.MX)) { EvaluateMx(domain, health.MXAnalysis, profile.Mx, result); }
        if (profile.StartTls == null || profile.StartTls.Enabled == false || CanEvaluate(HealthCheckType.STARTTLS)) { EvaluateStartTls(domain, health.StartTlsAnalysis, profile.StartTls, result); }
        if (profile.SmtpTls == null || profile.SmtpTls.Enabled == false || CanEvaluate(HealthCheckType.SMTPTLS)) { EvaluateSmtpTls(domain, health.SmtpTlsAnalysis, profile.SmtpTls, result); }
        if (profile.ImapTls == null || profile.ImapTls.Enabled == false || CanEvaluate(HealthCheckType.IMAPTLS)) { EvaluateImapTls(domain, health.ImapTlsAnalysis, profile.ImapTls, result); }
        if (profile.Pop3Tls == null || profile.Pop3Tls.Enabled == false || CanEvaluate(HealthCheckType.POP3TLS)) { EvaluatePop3Tls(domain, health.Pop3TlsAnalysis, profile.Pop3Tls, result); }
        if (profile.SmtpBanner == null || profile.SmtpBanner.Enabled == false || CanEvaluate(HealthCheckType.SMTPBANNER)) { EvaluateSmtpBanner(domain, health.SmtpBannerAnalysis, profile.SmtpBanner, result); }
        if (profile.SmtpAuth == null || profile.SmtpAuth.Enabled == false || CanEvaluate(HealthCheckType.SMTPAUTH)) { EvaluateSmtpAuth(domain, health.SmtpAuthAnalysis, profile.SmtpAuth, result); }
        if (profile.OpenRelay == null || profile.OpenRelay.Enabled == false || CanEvaluate(HealthCheckType.OPENRELAY)) { EvaluateOpenRelay(domain, health.OpenRelayAnalysis, profile.OpenRelay, result); }
        if (profile.MailLatency == null || profile.MailLatency.Enabled == false || CanEvaluate(HealthCheckType.MAILLATENCY)) { EvaluateMailLatency(domain, health.MailLatencyAnalysis, profile.MailLatency, result); }
        if (profile.OpenResolver == null || profile.OpenResolver.Enabled == false || CanEvaluate(HealthCheckType.OPENRESOLVER)) { EvaluateOpenResolver(domain, health.OpenResolverAnalysis, profile.OpenResolver, result); }
        if (profile.ReverseDns == null || profile.ReverseDns.Enabled == false || CanEvaluate(HealthCheckType.REVERSEDNS)) { EvaluateReverseDns(domain, health.ReverseDnsAnalysis, profile.ReverseDns, result); }
        if (profile.FcrDns == null || profile.FcrDns.Enabled == false || CanEvaluate(HealthCheckType.FCRDNS)) { EvaluateFcrDns(domain, health.FcrDnsAnalysis, profile.FcrDns, result); }
        if (profile.Ns == null || profile.Ns.Enabled == false || CanEvaluate(HealthCheckType.NS)) { EvaluateNs(domain, health.NSAnalysis, profile.Ns, result); }
        if (profile.DanglingCname == null || profile.DanglingCname.Enabled == false || CanEvaluate(HealthCheckType.DANGLINGCNAME)) { EvaluateDanglingCname(domain, health.DanglingCnameAnalysis, profile.DanglingCname, result); }
        if (profile.Caa == null || profile.Caa.Enabled == false || CanEvaluate(HealthCheckType.CAA)) { EvaluateCaa(domain, health.CAAAnalysis, profile.Caa, result); }
        if (profile.DnsSec == null || profile.DnsSec.Enabled == false || CanEvaluate(HealthCheckType.DNSSEC)) { EvaluateDnssec(domain, health.DnsSecAnalysis, profile.DnsSec, result); }
        if (profile.Soa == null || profile.Soa.Enabled == false || CanEvaluate(HealthCheckType.SOA)) { EvaluateSoa(domain, health.SOAAnalysis, profile.Soa, result); }
        if (profile.Dane == null || profile.Dane.Enabled == false || CanEvaluate(HealthCheckType.DANE)) { EvaluateDane(domain, health.DaneAnalysis, profile.Dane, result); }
        if (profile.Dnsbl == null || profile.Dnsbl.Enabled == false || CanEvaluate(HealthCheckType.DNSBL)) { EvaluateDnsbl(domain, health.DNSBLAnalysis, profile.Dnsbl, result); }
        if (profile.DnsHealth == null || profile.DnsHealth.Enabled == false || CanEvaluate(HealthCheckType.DNSHEALTH)) { EvaluateDnsHealth(domain, health.DnsHealthAnalysis, profile.DnsHealth, result); }
        if (profile.ApexAddress == null || profile.ApexAddress.Enabled == false || CanEvaluate(HealthCheckType.APEXADDRESS)) { EvaluateApexAddress(domain, health.ApexAddressAnalysis, profile.ApexAddress, result); }
        if (profile.Rpki == null || profile.Rpki.Enabled == false || CanEvaluate(HealthCheckType.RPKI)) { EvaluateRpki(domain, health.RpkiAnalysis, profile.Rpki, result); }
        if (profile.EdnsSupport == null || profile.EdnsSupport.Enabled == false || CanEvaluate(HealthCheckType.EDNSSUPPORT)) { EvaluateEdnsSupport(domain, health.EdnsSupportAnalysis, profile.EdnsSupport, result); }
        if (profile.DnsOverTls == null || profile.DnsOverTls.Enabled == false || CanEvaluate(HealthCheckType.DNSOVERTLS)) { EvaluateDnsOverTls(domain, health.DnsOverTlsAnalysis, profile.DnsOverTls, result); }
        if (profile.FlatteningService == null || profile.FlatteningService.Enabled == false || CanEvaluate(HealthCheckType.FLATTENINGSERVICE)) { EvaluateFlatteningService(domain, health.FlatteningServiceAnalysis, profile.FlatteningService, result); }
        if (profile.Delegation == null || profile.Delegation.Enabled == false || CanEvaluate(HealthCheckType.DELEGATION)) { EvaluateDelegation(domain, health.NSAnalysis, profile.Delegation, result); }
        if (profile.ZoneTransfer == null || profile.ZoneTransfer.Enabled == false || CanEvaluate(HealthCheckType.ZONETRANSFER)) { EvaluateZoneTransfer(domain, health.ZoneTransferAnalysis, profile.ZoneTransfer, result); }
        if (profile.WildcardDns == null || profile.WildcardDns.Enabled == false || CanEvaluate(HealthCheckType.WILDCARDDNS)) { EvaluateWildcardDns(domain, health.WildcardDnsAnalysis, profile.WildcardDns, result); }
        if (profile.Ttl == null || profile.Ttl.Enabled == false || CanEvaluate(HealthCheckType.TTL)) { EvaluateTtl(domain, health.DnsTtlAnalysis, profile.Ttl, result); }
        if (profile.Autodiscover == null || profile.Autodiscover.Enabled == false || CanEvaluate(HealthCheckType.AUTODISCOVER)) { EvaluateAutodiscover(domain, health.AutodiscoverAnalysis, profile.Autodiscover, result); }
        if (profile.SecurityTxt == null || profile.SecurityTxt.Enabled == false || CanEvaluate(HealthCheckType.SECURITYTXT)) { EvaluateSecurityTxt(domain, health.SecurityTXTAnalysis, profile.SecurityTxt, result); }
        if (profile.Robots == null || profile.Robots.Enabled == false || CanEvaluate(HealthCheckType.ROBOTS)) { EvaluateRobots(domain, health.RobotsTxtAnalysis, profile.Robots, result); }
        if (profile.AgentReadiness == null || profile.AgentReadiness.Enabled == false || CanEvaluate(HealthCheckType.AGENTREADINESS)) { EvaluateAgentReadiness(domain, health.AgentReadinessAnalysis, profile.AgentReadiness, result); }

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

    /// <summary>Executes the apply assessment policy operation.</summary>
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

    /// <summary>Executes the apply assessment policy operation.</summary>
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
