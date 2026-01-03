using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public static class DesiredStateEvaluator {
    public static DesiredStateAnalysis Evaluate(string domain, DomainHealthCheck health, DesiredStateProfile profile, MailDomainClassificationCategory? classification = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
            throw new ArgumentNullException(nameof(domain));
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
        } catch {
            // Policy application should not prevent desired state evaluation.
        }

        try {
            AppendHealthAssessments(health, result);
        } catch {
            // Collection should not prevent desired state evaluation.
        }

        EvaluateDmarc(domain, health.DmarcAnalysis, profile.Dmarc, result);
        EvaluateSpf(domain, health.SpfAnalysis, profile.Spf, result);
        EvaluateDkim(domain, health.DKIMAnalysis, profile.Dkim, result);
        EvaluateMtasts(domain, health.MTASTSAnalysis, profile.Mtasts, result);
        EvaluateTlsRpt(domain, health.TLSRPTAnalysis, profile.TlsRpt, result);
        EvaluateBimi(domain, health.BimiAnalysis, profile.Bimi, result);

        // Apply policy so users can suppress/override DesiredState.* codes as well.
        try {
            ApplyAssessmentPolicy(result, profile.AssessmentPolicy);
        } catch {
        }

        var hasProblems = result.Assessments.Any(a => a.Severity != AssessmentSeverity.Info);
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
            } catch {
            }
        }
        return result;
    }

    public static void ApplyAssessmentPolicy(DomainHealthCheck health, DesiredStateAssessmentPolicy? policy) {
        if (health == null || policy == null) return;

        var suppress = new HashSet<string>(policy.SuppressCodes ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var overrides = policy.SeverityOverrides ?? new Dictionary<string, AssessmentSeverity>(StringComparer.OrdinalIgnoreCase);

        var props = typeof(DomainHealthCheck)
            .GetProperties(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public)
            .Where(p => typeof(IHasAssessments).IsAssignableFrom(p.PropertyType))
            .ToArray();

        foreach (var pi in props) {
            object? value;
            try { value = pi.GetValue(health); } catch { continue; }
            if (value is IHasAssessments has && has.Assessments != null) {
                ApplyAssessmentPolicy(has, suppress, overrides);
            }
        }
    }

    private static void AppendHealthAssessments(DomainHealthCheck health, DesiredStateAnalysis sink) {
        if (health == null) return;
        if (sink == null) return;

        var props = typeof(DomainHealthCheck)
            .GetProperties(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public)
            .Where(p => typeof(IHasAssessments).IsAssignableFrom(p.PropertyType))
            .ToArray();

        foreach (var pi in props) {
            object? value;
            try { value = pi.GetValue(health); } catch { continue; }
            if (value is IHasAssessments has && has.Assessments != null && has.Assessments.Count > 0) {
                foreach (var a in has.Assessments) {
                    if (a == null) continue;
                    sink.Assessments.Add(CloneAssessment(a));
                }
            }
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
                var code = list[i].Code;
                if (!string.IsNullOrWhiteSpace(code) && suppress.Contains(code!)) {
                    list.RemoveAt(i);
                }
            }
        }

        if (overrides.Count > 0) {
            foreach (var a in list) {
                if (a == null) continue;
                var code = a.Code;
                if (!string.IsNullOrWhiteSpace(code) && overrides.TryGetValue(code!, out var sev)) {
                    a.Severity = sev;
                }
            }
        }
    }

    private static void EvaluateDmarc(string domain, DmarcAnalysis dmarc, DesiredStateDmarcPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !dmarc.DmarcRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcMissingRecord,
                Message = "Desired state requires a DMARC record, but none was found."
            });
            return;
        }

        if (!dmarc.DmarcRecordExists) {
            return;
        }

        if (desired.AllowedPolicies != null && desired.AllowedPolicies.Length > 0) {
            var actual = (dmarc.PolicyShort ?? string.Empty).Trim().ToLowerInvariant();
            var allowed = desired.AllowedPolicies
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p.Trim().ToLowerInvariant())
                .ToArray();
            if (allowed.Length > 0 && !allowed.Contains(actual)) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DmarcPolicyNotAllowed,
                    Message = $"Desired state requires DMARC policy in [{string.Join(", ", allowed)}], but found '{actual}'."
                });
            }
        }

        var ruaCount = (dmarc.MailtoRua?.Count ?? 0) + (dmarc.HttpRua?.Count ?? 0);
        if (desired.RequireRua == true && ruaCount == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcRuaMissing,
                Message = "Desired state requires DMARC aggregate reporting (rua), but none was configured."
            });
        }

        if (desired.AllowedReportDomainSuffixes != null && desired.AllowedReportDomainSuffixes.Length > 0) {
            var suffixes = desired.AllowedReportDomainSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .ToArray();

            if (suffixes.Length > 0) {
                foreach (var reportDomain in EnumerateReportDomains(dmarc)) {
                    var ok = suffixes.Any(s => reportDomain.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.DmarcRuaDomainNotAllowed,
                            Message = $"Desired state requires DMARC reporting domains to end with [{string.Join(", ", suffixes)}], but found '{reportDomain}'."
                        });
                    }
                }
            }
        }

        if (desired.RequireExternalReportAuthorization == true && dmarc.ExternalReportAuthorization != null && dmarc.ExternalReportAuthorization.Count > 0) {
            foreach (var kvp in dmarc.ExternalReportAuthorization) {
                if (!kvp.Value) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.DmarcExternalReportUnauthorized,
                        Message = $"External reporting domain '{kvp.Key}' is not authorized via _report._dmarc."
                    });
                }
            }
        }
    }

    private static IEnumerable<string> EnumerateReportDomains(DmarcAnalysis dmarc) {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddMailto(IEnumerable<string>? addresses) {
            if (addresses == null) return;
            foreach (var m in addresses) {
                if (string.IsNullOrWhiteSpace(m)) continue;
                var at = m.IndexOf('@');
                if (at > -1 && at < m.Length - 1) {
                    var dom = m.Substring(at + 1).Trim().Trim('.');
                    if (dom.Length > 0) set.Add(dom);
                }
            }
        }

        void AddHttp(IEnumerable<string>? uris) {
            if (uris == null) return;
            foreach (var u in uris) {
                if (string.IsNullOrWhiteSpace(u)) continue;
                if (Uri.TryCreate(u, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host)) {
                    var host = uri.Host.Trim().Trim('.');
                    if (host.Length > 0) set.Add(host);
                }
            }
        }

        AddMailto(dmarc.MailtoRua);
        AddMailto(dmarc.MailtoRuf);
        AddHttp(dmarc.HttpRua);
        AddHttp(dmarc.HttpRuf);

        return set;
    }

    private static void EvaluateSpf(string domain, SpfAnalysis spf, DesiredStateSpfPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !spf.SpfRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfMissingRecord,
                Message = "Desired state requires an SPF record, but none was found."
            });
            return;
        }

        if (!spf.SpfRecordExists) {
            return;
        }

        if (desired.AllowedAllMechanisms != null && desired.AllowedAllMechanisms.Length > 0) {
            var allowed = desired.AllowedAllMechanisms
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Select(a => a.Trim())
                .ToArray();
            var actual = spf.AllMechanism?.Trim() ?? string.Empty;
            if (allowed.Length > 0 && !allowed.Contains(actual, StringComparer.OrdinalIgnoreCase)) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SpfAllMechanismNotAllowed,
                    Message = $"Desired state requires SPF all mechanism in [{string.Join(", ", allowed)}], but found '{actual}'."
                });
            }
        }

        if (desired.MaxDnsLookups.HasValue) {
            var max = desired.MaxDnsLookups.Value;
            if (spf.DnsLookupsCount > max) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SpfDnsLookupsExceeded,
                    Message = $"Desired state requires SPF DNS lookups <= {max}, but found {spf.DnsLookupsCount}."
                });
            }
        }

        if (desired.RequireDenyAll == true && !spf.DenyAll) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfDenyAllRequired,
                Message = "Desired state requires SPF to deny all sending (e.g., v=spf1 -all)."
            });
        }
    }

    private static void EvaluateDkim(string domain, DkimAnalysis dkim, DesiredStateDkimPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        var requiredSelectors = desired.RequiredSelectors?
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        DkimRecordAnalysis? FindSelector(string selector) {
            foreach (var kvp in dkim.AnalysisResults!) {
                if (string.Equals(kvp.Key, selector, StringComparison.OrdinalIgnoreCase)) {
                    return kvp.Value;
                }
            }
            return null;
        }

        if (desired.RequireAtLeastOneSelector == true && dkim.AnalysisResults.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimNoSelectors,
                Message = "Desired state requires DKIM selectors to be present, but none were analyzed."
            });
        }

        if (requiredSelectors != null && requiredSelectors.Length > 0) {
            foreach (var selector in requiredSelectors) {
                var analysis = FindSelector(selector);
                if (analysis == null || !analysis.DkimRecordExists) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.DkimSelectorMissing,
                        Message = $"Desired state requires DKIM selector '{selector}', but no DKIM record was found."
                    });
                    continue;
                }

                EvaluateDkimSelector(domain, selector, analysis, desired, sink);
            }
            return;
        }

        foreach (var kvp in dkim.AnalysisResults!) {
            var selector = kvp.Key;
            var analysis = kvp.Value;
            if (analysis == null || !analysis.DkimRecordExists) continue;
            EvaluateDkimSelector(domain, selector, analysis, desired, sink);
        }
    }

    private static void EvaluateDkimSelector(string domain, string selector, DkimRecordAnalysis analysis, DesiredStateDkimPolicy desired, DesiredStateAnalysis sink) {
        if (desired.MinKeyBits.HasValue) {
            var minBits = desired.MinKeyBits.Value;
            if (analysis.KeyLength > 0 && analysis.KeyLength < minBits) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DkimKeyBitsTooLow,
                    Message = $"Desired state requires DKIM key length >= {minBits} bits for selector '{selector}', but found {analysis.KeyLength}."
                });
            }
        }

        if (desired.AllowedCnameTargetSuffixes != null && desired.AllowedCnameTargetSuffixes.Length > 0) {
            var suffixes = desired.AllowedCnameTargetSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .ToArray();

            if (suffixes.Length > 0) {
                var target = (analysis.CnameTarget ?? string.Empty).Trim().Trim('.');
                var ok = target.Length > 0 && suffixes.Any(s => target.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                if (!ok) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.DkimCnameTargetNotAllowed,
                        Message = $"Desired state requires DKIM selector '{selector}' CNAME target to end with [{string.Join(", ", suffixes)}], but found '{target}'."
                    });
                }
            }
        }
    }

    private static void EvaluateMtasts(string domain, MTASTSAnalysis mtasts, DesiredStateMtastsPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !mtasts.DnsRecordPresent) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MtastsMissingRecord,
                Message = "Desired state requires an MTA-STS record, but none was found."
            });
            return;
        }

        if (!mtasts.DnsRecordPresent) {
            return;
        }

        if (desired.RequireEnforce == true && !mtasts.EnforcesMtaSts) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MtastsEnforceRequired,
                Message = "Desired state requires MTA-STS to be in enforce mode."
            });
        }

        if (desired.MinMaxAge.HasValue) {
            var min = desired.MinMaxAge.Value;
            if (mtasts.MaxAge < min) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.MtastsMaxAgeTooLow,
                    Message = $"Desired state requires MTA-STS max_age >= {min}, but found {mtasts.MaxAge}."
                });
            }
        }

        if (desired.RequireMxAligned == true && mtasts.PolicyPresent && !mtasts.MxAligned) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MtastsMxNotAligned,
                Message = "Desired state requires MTA-STS policy MX patterns to cover all MX hosts."
            });
        }
    }

    private static void EvaluateTlsRpt(string domain, TLSRPTAnalysis tlsrpt, DesiredStateTlsRptPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !tlsrpt.TlsRptRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TlsRptMissingRecord,
                Message = "Desired state requires a TLSRPT record, but none was found."
            });
            return;
        }

        if (!tlsrpt.TlsRptRecordExists) {
            return;
        }

        if (desired.RequireRua == true && !tlsrpt.RuaDefined) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TlsRptRuaMissing,
                Message = "Desired state requires TLSRPT reporting (rua), but none was configured."
            });
        }

        if (desired.RequireValidPolicy == true && !tlsrpt.PolicyValid) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TlsRptPolicyInvalid,
                Message = "Desired state requires a valid TLSRPT policy (v=TLSRPTv1 + rua)."
            });
        }

        if (desired.AllowedReportDomainSuffixes != null && desired.AllowedReportDomainSuffixes.Length > 0) {
            var suffixes = desired.AllowedReportDomainSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .ToArray();

            if (suffixes.Length > 0) {
                foreach (var reportDomain in EnumerateTlsRptReportDomains(tlsrpt)) {
                    var ok = suffixes.Any(s => reportDomain.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.TlsRptRuaDomainNotAllowed,
                            Message = $"Desired state requires TLSRPT reporting domains to end with [{string.Join(", ", suffixes)}], but found '{reportDomain}'."
                        });
                    }
                }
            }
        }
    }

    private static IEnumerable<string> EnumerateTlsRptReportDomains(TLSRPTAnalysis tlsrpt) {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddMailto(IEnumerable<string>? addresses) {
            if (addresses == null) return;
            foreach (var m in addresses) {
                if (string.IsNullOrWhiteSpace(m)) continue;
                var at = m.IndexOf('@');
                if (at > -1 && at < m.Length - 1) {
                    var dom = m.Substring(at + 1).Trim().Trim('.');
                    if (dom.Length > 0) set.Add(dom);
                }
            }
        }

        void AddHttp(IEnumerable<string>? uris) {
            if (uris == null) return;
            foreach (var u in uris) {
                if (string.IsNullOrWhiteSpace(u)) continue;
                if (Uri.TryCreate(u, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host)) {
                    var host = uri.Host.Trim().Trim('.');
                    if (host.Length > 0) set.Add(host);
                }
            }
        }

        AddMailto(tlsrpt.MailtoRua);
        AddHttp(tlsrpt.HttpRua);

        return set;
    }

    private static void EvaluateBimi(string domain, BimiAnalysis bimi, DesiredStateBimiPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !bimi.BimiRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.BimiMissingRecord,
                Message = "Desired state requires a BIMI record, but none was found."
            });
            return;
        }

        if (!bimi.BimiRecordExists) {
            return;
        }

        if (desired.RequireIndicator == true && bimi.DeclinedToPublish) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.BimiIndicatorDeclined,
                Message = "Desired state requires a BIMI indicator, but the domain declined to publish one (l= and a= are empty)."
            });
        }

        var location = bimi.Location?.Trim();
        if (desired.RequireValidLocation == true) {
            if (string.IsNullOrWhiteSpace(location) || bimi.InvalidLocation) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.BimiLocationInvalid,
                    Message = "Desired state requires a valid BIMI location (https://...svg/.svgz), but it was missing or invalid."
                });
            }
        }

        if (desired.AllowedLocationHostSuffixes != null && desired.AllowedLocationHostSuffixes.Length > 0) {
            var suffixes = desired.AllowedLocationHostSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (suffixes.Length > 0) {
                var host = TryGetHost(location);
                if (string.IsNullOrWhiteSpace(host)) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.BimiLocationHostNotAllowed,
                        Message = $"Desired state requires BIMI location host to end with [{string.Join(", ", suffixes)}], but no valid host was found."
                    });
                } else {
                    var ok = suffixes.Any(s => host.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.BimiLocationHostNotAllowed,
                            Message = $"Desired state requires BIMI location host to end with [{string.Join(", ", suffixes)}], but found '{host}'."
                        });
                    }
                }
            }
        }

        var authority = bimi.Authority?.Trim();
        if (desired.RequireAuthority == true && string.IsNullOrWhiteSpace(authority)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.BimiAuthorityMissing,
                Message = "Desired state requires a BIMI authority (VMC) URL, but none was configured."
            });
        }

        if (desired.AllowedAuthorityHostSuffixes != null && desired.AllowedAuthorityHostSuffixes.Length > 0) {
            var suffixes = desired.AllowedAuthorityHostSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (suffixes.Length > 0 && !string.IsNullOrWhiteSpace(authority)) {
                var host = TryGetHost(authority);
                if (string.IsNullOrWhiteSpace(host)) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.BimiAuthorityHostNotAllowed,
                        Message = $"Desired state requires BIMI authority host to end with [{string.Join(", ", suffixes)}], but no valid host was found."
                    });
                } else {
                    var ok = suffixes.Any(s => host.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.BimiAuthorityHostNotAllowed,
                            Message = $"Desired state requires BIMI authority host to end with [{string.Join(", ", suffixes)}], but found '{host}'."
                        });
                    }
                }
            }
        }
    }

    private static string? TryGetHost(string? uriString) {
        if (string.IsNullOrWhiteSpace(uriString)) return null;
        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri)) return null;
        if (string.IsNullOrWhiteSpace(uri.Host)) return null;
        return uri.Host.Trim().Trim('.');
    }
}
