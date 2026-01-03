using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    private static void EvaluateSmtpBanner(string domain, SMTPBannerAnalysis analysis, DesiredStateSmtpBannerPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var results = analysis.ServerResults ?? new Dictionary<string, SMTPBannerAnalysis.BannerResult>();

        if (desired.RequireAtLeastOneResult == true && results.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SmtpBannerNoResults,
                Message = "Desired state expected SMTP banner results, but no results were produced."
            });
            return;
        }

        if (results.Count == 0) {
            return;
        }

        var allowedSuffixes = desired.AllowedServerDomainSuffixes?
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim().Trim('.'))
            .Where(s => s.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray() ?? Array.Empty<string>();

	        var versionLeakTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
	        if (desired.DisallowVersionLeak == true && analysis.Assessments != null && analysis.Assessments.Count > 0) {
	            foreach (var a in analysis.Assessments) {
	                if (a == null) continue;
	                if (!string.Equals(a.Code, SmtpBannerCodes.VersionLeaked, StringComparison.OrdinalIgnoreCase)) continue;
	                if (a.Target == null) continue;
	
	                var target = a.Target.Trim();
	                if (target.Length == 0) continue;
	
	                versionLeakTargets.Add(target);
	            }
	        }

        foreach (var kvp in results) {
            var key = kvp.Key;
            var r = kvp.Value;
            if (r == null) continue;

            if (desired.RequireValidFormat == true && !r.ValidFormat) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SmtpBannerFormatInvalid,
                    Message = $"Desired state requires an RFC-compliant SMTP banner, but '{key}' banner format was invalid."
                });
            }

            if (desired.RequireStartsWith220 == true && !r.StartsWith220) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SmtpBannerGreetingNot220,
                    Message = $"Desired state requires SMTP banners to start with 220, but '{key}' did not."
                });
            }

            if (desired.RequireDomainPresent == true && !r.ContainsDomain) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SmtpBannerDomainMissing,
                    Message = $"Desired state requires SMTP banners to include a domain name, but '{key}' did not."
                });
            }

            if (desired.DisallowTruncated == true && r.Truncated) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SmtpBannerTruncatedNotAllowed,
                    Message = $"Desired state disallows truncated SMTP banners, but '{key}' banner was truncated."
                });
            }

            if (desired.MaxResponseTimeMs.HasValue && r.ResponseTimeMs.HasValue && r.ResponseTimeMs.Value > desired.MaxResponseTimeMs.Value) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SmtpBannerResponseTimeTooHigh,
                    Message = $"Desired state requires SMTP banner response time <= {desired.MaxResponseTimeMs.Value} ms, but '{key}' responded in {r.ResponseTimeMs.Value} ms."
                });
            }

            if (desired.RequireTlsAdvertised == true && !r.TlsAdvertised) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SmtpBannerTlsNotAdvertised,
                    Message = $"Desired state requires SMTP banners to advertise TLS, but '{key}' did not."
                });
            }

            if (allowedSuffixes.Length > 0) {
                var serverDomain = (r.ServerDomain ?? string.Empty).Trim().Trim('.');
                if (string.IsNullOrWhiteSpace(serverDomain)) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.SmtpBannerDomainMissing,
                        Message = $"Desired state requires SMTP banners to include a domain name ending with [{string.Join(", ", allowedSuffixes)}], but '{key}' had no domain."
                    });
                } else if (!allowedSuffixes.Any(s => serverDomain.EndsWith(s, StringComparison.OrdinalIgnoreCase))) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.SmtpBannerServerDomainNotAllowed,
                        Message = $"Desired state requires SMTP banner domains to end with [{string.Join(", ", allowedSuffixes)}], but '{key}' contained '{serverDomain}'."
                    });
                }
            }

            if (desired.DisallowVersionLeak == true && versionLeakTargets.Contains(key)) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SmtpBannerVersionLeakNotAllowed,
                    Message = $"Desired state disallows SMTP banners leaking software versions, but '{key}' exposed a version."
                });
            }
        }
    }

    private static void EvaluateSmtpAuth(string domain, SmtpAuthAnalysis analysis, DesiredStateSmtpAuthPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var mechanismsByServer = analysis.ServerMechanisms ?? new Dictionary<string, string[]>();

        if (desired.RequireAtLeastOneResult == true && mechanismsByServer.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SmtpAuthNoResults,
                Message = "Desired state expected SMTP AUTH results, but no results were produced."
            });
            return;
        }

        if (mechanismsByServer.Count == 0) {
            return;
        }

        var allowed = desired.AllowedMechanisms?
            .Where(m => !string.IsNullOrWhiteSpace(m))
            .Select(m => m.Trim())
            .Where(m => m.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var disallowed = desired.DisallowedMechanisms?
            .Where(m => !string.IsNullOrWhiteSpace(m))
            .Select(m => m.Trim())
            .Where(m => m.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var requiredAnyOf = desired.RequiredMechanismsAnyOf?
            .Where(m => !string.IsNullOrWhiteSpace(m))
            .Select(m => m.Trim())
            .Where(m => m.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase) ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var kvp in mechanismsByServer) {
            var key = kvp.Key;
            var mechs = kvp.Value ?? Array.Empty<string>();
            var hasAuth = mechs.Length > 0;

            if (desired.DisallowAuthAdvertisement == true && hasAuth) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SmtpAuthAdvertisementNotAllowed,
                    Message = $"Desired state disallows SMTP AUTH, but '{key}' advertised AUTH mechanisms: {string.Join(" ", mechs)}."
                });
                continue;
            }

            if (!hasAuth) {
                continue;
            }

            if (allowed.Count > 0) {
                foreach (var m in mechs.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim())) {
                    if (!allowed.Contains(m)) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.SmtpAuthMechanismUnexpected,
                            Message = $"Desired state restricts SMTP AUTH mechanisms to [{string.Join(", ", allowed)}], but '{key}' advertised '{m}'."
                        });
                    }
                }
            }

            if (disallowed.Count > 0) {
                foreach (var m in mechs.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim())) {
                    if (disallowed.Contains(m)) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.SmtpAuthMechanismNotAllowed,
                            Message = $"Desired state disallows SMTP AUTH mechanism '{m}', but '{key}' advertised it."
                        });
                    }
                }
            }

            if (requiredAnyOf.Count > 0) {
                var present = mechs.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (!present.Overlaps(requiredAnyOf)) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.SmtpAuthRequiredMechanismMissing,
                        Message = $"Desired state requires at least one SMTP AUTH mechanism from [{string.Join(", ", requiredAnyOf)}], but '{key}' advertised: {string.Join(" ", mechs)}."
                    });
                }
            }

            if (desired.RequireStartTlsCapabilityWhenAuth == true) {
                if (analysis.ServerCapabilities == null || !analysis.ServerCapabilities.TryGetValue(key, out var caps) || caps == null || caps.Length == 0) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.SmtpAuthCapabilitiesMissing,
                        Message = $"Desired state requires STARTTLS to be evaluated alongside AUTH, but capabilities were not captured for '{key}'."
                    });
                } else if (!caps.Any(c => string.Equals(c, "STARTTLS", StringComparison.OrdinalIgnoreCase))) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.SmtpAuthStartTlsRequired,
                        Message = $"Desired state requires STARTTLS to be advertised when AUTH is present, but '{key}' did not advertise STARTTLS."
                    });
                }
            }
        }
    }

    private static void EvaluateOpenRelay(string domain, OpenRelayAnalysis analysis, DesiredStateOpenRelayPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var results = analysis.ServerResults ?? new Dictionary<string, OpenRelayAnalysis.OpenRelayResult>();

        if (desired.RequireAtLeastOneResult == true && results.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.OpenRelayNoResults,
                Message = "Desired state expected open relay results, but no results were produced."
            });
            return;
        }

        if (results.Count == 0) {
            return;
        }

        foreach (var kvp in results) {
            var key = kvp.Key;
            var r = kvp.Value;
            if (r == null) continue;

            if (desired.DisallowOpenRelay == true && r.Status == OpenRelayStatus.AllowsRelay) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.OpenRelayNotAllowed,
                    Message = $"Desired state disallows open relay, but '{key}' allowed unauthenticated relay."
                });
            }

            if (desired.TreatConnectionFailuresAsDrift == true && r.Status == OpenRelayStatus.ConnectionFailed) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.OpenRelayConnectionFailed,
                    Message = $"Desired state expected open relay checks to complete, but '{key}' connection failed."
                });
            }
        }
    }

    private static void EvaluateMailLatency(string domain, MailLatencyAnalysis analysis, DesiredStateMailLatencyPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var results = analysis.ServerResults ?? new Dictionary<string, MailLatencyAnalysis.LatencyResult>();

        if (desired.RequireAtLeastOneResult == true && results.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MailLatencyNoResults,
                Message = "Desired state expected mail latency results, but no results were produced."
            });
            return;
        }

        if (results.Count == 0) {
            return;
        }

        foreach (var kvp in results) {
            var key = kvp.Key;
            var r = kvp.Value;
            if (r == null) continue;

            if (desired.RequireAllConnectSuccess == true && !r.ConnectSuccess) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.MailLatencyConnectFailed,
                    Message = $"Desired state requires mail servers to be reachable, but '{key}' connection failed."
                });
            }

            if (desired.RequireAllBannerSuccess == true && !r.BannerSuccess) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.MailLatencyBannerFailed,
                    Message = $"Desired state requires mail servers to return an SMTP banner, but '{key}' banner read failed."
                });
            }

            if (desired.MaxConnectTimeMs.HasValue) {
                var ms = (int)Math.Round(r.ConnectTime.TotalMilliseconds);
                if (ms > desired.MaxConnectTimeMs.Value) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.MailLatencyConnectTooSlow,
                        Message = $"Desired state requires connect time <= {desired.MaxConnectTimeMs.Value} ms, but '{key}' took {ms} ms."
                    });
                }
            }

            if (desired.MaxBannerTimeMs.HasValue) {
                var ms = (int)Math.Round(r.BannerTime.TotalMilliseconds);
                if (ms > desired.MaxBannerTimeMs.Value) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.MailLatencyBannerTooSlow,
                        Message = $"Desired state requires banner time <= {desired.MaxBannerTimeMs.Value} ms, but '{key}' took {ms} ms."
                    });
                }
            }
        }
    }
}
