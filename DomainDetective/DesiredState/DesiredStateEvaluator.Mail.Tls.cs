using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    private static void EvaluateStartTls(string domain, STARTTLSAnalysis analysis, DesiredStateStartTlsPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var results = analysis.ServerResults ?? new Dictionary<string, bool>();

        if (desired.RequireAtLeastOneResult == true && results.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.StartTlsNoResults,
                Message = "Desired state expected STARTTLS results, but no results were produced."
            });
            return;
        }

        if (results.Count == 0) {
            return;
        }

        if (desired.RequireAnyServerSupported == true) {
            var any = results.Values.Any(v => v);
            if (!any) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.StartTlsAnySupportedRequired,
                    Message = "Desired state requires at least one server to support STARTTLS, but none did."
                });
            }
        }

        if (desired.RequireAllServersSupported == true) {
            foreach (var kvp in results) {
                if (!kvp.Value) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.StartTlsAllSupportedRequired,
                        Message = $"Desired state requires STARTTLS support on all servers, but '{kvp.Key}' did not support STARTTLS."
                    });
                }
            }
        }

        if (desired.DisallowDowngradeDetected == true && analysis.DowngradeDetected != null && analysis.DowngradeDetected.Count > 0) {
            foreach (var kvp in analysis.DowngradeDetected) {
                if (!kvp.Value) continue;
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.StartTlsDowngradeNotAllowed,
                    Message = $"Desired state disallows STARTTLS downgrade signals, but downgrade was detected for '{kvp.Key}'."
                });
            }
        }
    }

    private static void EvaluateSmtpTls(string domain, SMTPTLSAnalysis analysis, DesiredStateMailTlsPolicy? desired, DesiredStateAnalysis sink) {
        EvaluateMailTls(
            domain,
            analysis,
            desired,
            sink,
            DesiredStateCodes.SmtpTlsNoResults,
            DesiredStateCodes.SmtpTlsCertificateInvalid,
            DesiredStateCodes.SmtpTlsChainInvalid,
            DesiredStateCodes.SmtpTlsHostnameMismatch,
            DesiredStateCodes.SmtpTlsCertificateExpired,
            DesiredStateCodes.SmtpTlsCertificateExpiringSoon,
            DesiredStateCodes.SmtpTlsLegacyNotAllowed,
            DesiredStateCodes.SmtpTlsGradeTooLow);
    }

    private static void EvaluateImapTls(string domain, IMAPTLSAnalysis analysis, DesiredStateMailTlsPolicy? desired, DesiredStateAnalysis sink) {
        EvaluateMailTls(
            domain,
            analysis,
            desired,
            sink,
            DesiredStateCodes.ImapTlsNoResults,
            DesiredStateCodes.ImapTlsCertificateInvalid,
            DesiredStateCodes.ImapTlsChainInvalid,
            DesiredStateCodes.ImapTlsHostnameMismatch,
            DesiredStateCodes.ImapTlsCertificateExpired,
            DesiredStateCodes.ImapTlsCertificateExpiringSoon,
            DesiredStateCodes.ImapTlsLegacyNotAllowed,
            DesiredStateCodes.ImapTlsGradeTooLow);
    }

    private static void EvaluatePop3Tls(string domain, POP3TLSAnalysis analysis, DesiredStateMailTlsPolicy? desired, DesiredStateAnalysis sink) {
        EvaluateMailTls(
            domain,
            analysis,
            desired,
            sink,
            DesiredStateCodes.Pop3TlsNoResults,
            DesiredStateCodes.Pop3TlsCertificateInvalid,
            DesiredStateCodes.Pop3TlsChainInvalid,
            DesiredStateCodes.Pop3TlsHostnameMismatch,
            DesiredStateCodes.Pop3TlsCertificateExpired,
            DesiredStateCodes.Pop3TlsCertificateExpiringSoon,
            DesiredStateCodes.Pop3TlsLegacyNotAllowed,
            DesiredStateCodes.Pop3TlsGradeTooLow);
    }

    private static void EvaluateMailTls(
        string domain,
        MailTlsAnalysis analysis,
        DesiredStateMailTlsPolicy? desired,
        DesiredStateAnalysis sink,
        string noResultsCode,
        string certificateInvalidCode,
        string chainInvalidCode,
        string hostnameMismatchCode,
        string certificateExpiredCode,
        string certificateExpiringSoonCode,
        string legacyNotAllowedCode,
        string gradeTooLowCode) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var servers = analysis.ServerResults ?? new Dictionary<string, MailTlsAnalysis.TlsResult>();

        if (desired.RequireAtLeastOneResult == true && servers.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = noResultsCode,
                Message = "Desired state expected TLS results, but no results were produced."
            });
            return;
        }

        if (servers.Count == 0) {
            return;
        }

        foreach (var kvp in servers) {
            var key = kvp.Key;
            var r = kvp.Value;
            if (r == null) continue;

            if (desired.RequireCertificateValid == true && !r.CertificateValid) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = certificateInvalidCode,
                    Message = $"Desired state requires a valid certificate, but '{key}' did not present a valid certificate."
                });
            }

            if (desired.RequireChainValid == true && !r.ChainValid) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = chainInvalidCode,
                    Message = $"Desired state requires a valid certificate chain, but '{key}' chain validation failed."
                });
            }

            if (desired.RequireHostnameMatch == true && !r.HostnameMatch) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = hostnameMismatchCode,
                    Message = $"Desired state requires certificate hostname match, but '{key}' hostname did not match."
                });
            }

            if (desired.DisallowExpiredCertificates == true && r.IsExpired) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = certificateExpiredCode,
                    Message = $"Desired state disallows expired certificates, but '{key}' certificate is expired."
                });
            }

            if (desired.MinCertificateDaysToExpire.HasValue && r.DaysToExpire < desired.MinCertificateDaysToExpire.Value) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = certificateExpiringSoonCode,
                    Message = $"Desired state requires certificate days remaining >= {desired.MinCertificateDaysToExpire.Value}, but '{key}' has {r.DaysToExpire} days remaining."
                });
            }

            if (desired.DisallowLegacyProtocols == true && (r.SupportsTls10 || r.SupportsTls11 || r.LegacyEnabled)) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = legacyNotAllowedCode,
                    Message = $"Desired state disallows legacy TLS, but '{key}' offers or negotiated legacy protocols."
                });
            }

            if (desired.MinimumGradeLevel.HasValue) {
                var min = desired.MinimumGradeLevel.Value;
                if (r.GradeLevel == GradeLevel.Unknown || r.GradeLevel.IsBelow(min)) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = gradeTooLowCode,
                        Message = $"Desired state requires TLS grade >= {min}, but '{key}' is '{r.GradeLevel}'."
                    });
                }
            }
        }
    }
}

