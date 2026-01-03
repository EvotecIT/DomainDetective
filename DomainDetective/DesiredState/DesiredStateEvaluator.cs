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
        EvaluateMx(domain, health.MXAnalysis, profile.Mx, result);
        EvaluateNs(domain, health.NSAnalysis, profile.Ns, result);
        EvaluateCaa(domain, health.CAAAnalysis, profile.Caa, result);
        EvaluateDnssec(domain, health.DnsSecAnalysis, profile.DnsSec, result);
        EvaluateSoa(domain, health.SOAAnalysis, profile.Soa, result);
        EvaluateDane(domain, health.DaneAnalysis, profile.Dane, result);
        EvaluateDelegation(domain, health.NSAnalysis, profile.Delegation, result);
        EvaluateZoneTransfer(domain, health.ZoneTransferAnalysis, profile.ZoneTransfer, result);
        EvaluateWildcardDns(domain, health.WildcardDnsAnalysis, profile.WildcardDns, result);

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

        if (desired.RequireSubdomainPolicyTag == true && string.IsNullOrWhiteSpace(dmarc.SubPolicyShort)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcSubPolicyMissing,
                Message = "Desired state requires an explicit DMARC subdomain policy (sp=), but it was not present."
            });
        }

        if (desired.AllowedSubdomainPolicies != null && desired.AllowedSubdomainPolicies.Length > 0) {
            var actual = !string.IsNullOrWhiteSpace(dmarc.SubPolicyShort)
                ? dmarc.SubPolicyShort.Trim().ToLowerInvariant()
                : (dmarc.PolicyShort ?? string.Empty).Trim().ToLowerInvariant();

            var allowed = desired.AllowedSubdomainPolicies
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p.Trim().ToLowerInvariant())
                .ToArray();

            if (allowed.Length > 0 && !allowed.Contains(actual)) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DmarcSubPolicyNotAllowed,
                    Message = $"Desired state requires DMARC subdomain policy in [{string.Join(", ", allowed)}], but found '{actual}'."
                });
            }
        }

        if (desired.AllowedAspfAlignments != null && desired.AllowedAspfAlignments.Length > 0) {
            var actual = string.IsNullOrWhiteSpace(dmarc.SpfAShort) ? "r" : dmarc.SpfAShort.Trim().ToLowerInvariant();
            var allowed = desired.AllowedAspfAlignments
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Select(a => a.Trim().ToLowerInvariant())
                .ToArray();

            if (allowed.Length > 0 && !allowed.Contains(actual)) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DmarcAspfNotAllowed,
                    Message = $"Desired state requires DMARC aspf in [{string.Join(", ", allowed)}], but found '{actual}'."
                });
            }
        }

        if (desired.AllowedAdkimAlignments != null && desired.AllowedAdkimAlignments.Length > 0) {
            var actual = string.IsNullOrWhiteSpace(dmarc.DkimAShort) ? "r" : dmarc.DkimAShort.Trim().ToLowerInvariant();
            var allowed = desired.AllowedAdkimAlignments
                .Where(a => !string.IsNullOrWhiteSpace(a))
                .Select(a => a.Trim().ToLowerInvariant())
                .ToArray();

            if (allowed.Length > 0 && !allowed.Contains(actual)) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DmarcAdkimNotAllowed,
                    Message = $"Desired state requires DMARC adkim in [{string.Join(", ", allowed)}], but found '{actual}'."
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

        if (desired.RequiredIncludeDomains != null && desired.RequiredIncludeDomains.Length > 0) {
            var required = desired.RequiredIncludeDomains
                .Where(i => !string.IsNullOrWhiteSpace(i))
                .Select(i => i.Trim().Trim('.'))
                .Where(i => i.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (required.Length > 0) {
                var includes = (desired.MatchResolvedIncludes != false ? spf.ResolvedIncludeRecords : spf.IncludeRecords) ?? new List<string>();
                var present = new HashSet<string>(includes.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i.Trim().Trim('.')), StringComparer.OrdinalIgnoreCase);
                foreach (var inc in required) {
                    if (!present.Contains(inc)) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.SpfRequiredIncludeMissing,
                            Message = $"Desired state requires SPF include '{inc}', but it was not present."
                        });
                    }
                }
            }
        }

        if (desired.DisallowPtr == true && spf.HasPtrType) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfPtrNotAllowed,
                Message = "Desired state disallows the SPF ptr mechanism, but it was present."
            });
        }

        if (desired.DisallowUnknownMechanisms == true && spf.UnknownMechanisms != null && spf.UnknownMechanisms.Count > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfUnknownMechanismsNotAllowed,
                Message = $"Desired state disallows unknown SPF mechanisms/modifiers, but found: {string.Join(", ", spf.UnknownMechanisms)}."
            });
        }

        if (desired.DisallowRedirect == true && spf.HasRedirect) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfRedirectNotAllowed,
                Message = "Desired state disallows SPF redirect=, but it was present."
            });
        }

        if (desired.RequireRedirect == true && !spf.HasRedirect) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfRedirectRequired,
                Message = "Desired state requires SPF redirect=, but it was not present."
            });
        }

        if (desired.AllowedRedirectDomainSuffixes != null && desired.AllowedRedirectDomainSuffixes.Length > 0 && spf.HasRedirect) {
            var suffixes = desired.AllowedRedirectDomainSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var redirect = spf.RedirectValue?.Trim().Trim('.') ?? string.Empty;
            if (suffixes.Length > 0 && redirect.Length > 0) {
                var ok = suffixes.Any(s => redirect.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                if (!ok) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.SpfRedirectDomainNotAllowed,
                        Message = $"Desired state requires SPF redirect domain to end with [{string.Join(", ", suffixes)}], but found '{redirect}'."
                    });
                }
            }
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

    private static void EvaluateMx(string domain, MXAnalysis mx, DesiredStateMxPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !mx.MxRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxMissingRecord,
                Message = "Desired state requires MX records, but none were found."
            });
            return;
        }

        if (!mx.MxRecordExists) {
            return;
        }

        if (desired.RequireNullMx == true && !mx.HasNullMx) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxNullMxRequired,
                Message = "Desired state requires a Null MX (RFC 7505) record (0 .), but it was not found."
            });
        }

        if (desired.DisallowNullMx == true && mx.HasNullMx) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxNullMxNotAllowed,
                Message = "Desired state does not allow a Null MX record (0 .) for this domain."
            });
        }

        if (desired.AllowedHostSuffixes != null && desired.AllowedHostSuffixes.Length > 0) {
            var suffixes = desired.AllowedHostSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (suffixes.Length > 0) {
                foreach (var host in EnumerateMxHosts(mx)) {
                    var ok = suffixes.Any(s => host.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.MxHostNotAllowed,
                            Message = $"Desired state requires MX hosts to end with [{string.Join(", ", suffixes)}], but found '{host}'."
                        });
                    }
                }
            }
        }

        if (desired.RequireBackupServers == true && !mx.HasNullMx && !mx.HasBackupServers) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxBackupServersRequired,
                Message = "Desired state requires backup MX servers (multiple preferences), but only a single preference was detected."
            });
        }

        if (desired.RequireIpv6Supported == true && !mx.HasNullMx && !mx.Ipv6Supported) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxIpv6Required,
                Message = "Desired state requires MX hosts to have IPv6 (AAAA) support, but none was detected."
            });
        }

        if (desired.DisallowCnameTargets == true && mx.PointsToCname) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxTargetCnameNotAllowed,
                Message = "Desired state does not allow MX hostnames that point to CNAMEs."
            });
        }

        if (desired.DisallowIpTargets == true && mx.PointsToIpAddress) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxTargetIpNotAllowed,
                Message = "Desired state does not allow MX records that point directly to IP addresses."
            });
        }

        if (desired.DisallowNonExistentTargets == true && mx.PointsToNonExistentDomain) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxTargetNonExistent,
                Message = "Desired state does not allow MX records that point to non-existent domains."
            });
        }

        if (desired.DisallowNoAddressTargets == true && mx.PointsToDomainWithoutAOrAaaaRecord) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxTargetNoAddress,
                Message = "Desired state does not allow MX records that point to domains without A/AAAA records."
            });
        }

        if (desired.DisallowLocalhostTargets == true && mx.PointsToLocalhost) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxTargetLocalhostNotAllowed,
                Message = "Desired state does not allow MX targets that point to localhost."
            });
        }

        if (desired.RequireTtlUniform == true && !mx.MxTtlUniform) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxTtlNotUniform,
                Message = "Desired state requires MX TTL values to be uniform across answers."
            });
        }

        if (desired.RequireRrsetConsistentAcrossNs == true && !mx.MxRrsetConsistentAcrossNs) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxRrsetInconsistent,
                Message = "Desired state requires MX RRset to be consistent across authoritative name servers."
            });
        }

        if (desired.RequireTargetAddressConsistentAcrossNs == true && !mx.TargetAddressConsistentAcrossNs) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.MxTargetAddressInconsistent,
                Message = "Desired state requires MX target addresses to be consistent across authoritative name servers."
            });
        }
    }

    private static IEnumerable<string> EnumerateMxHosts(MXAnalysis mx) {
        if (mx == null) {
            yield break;
        }
        if (mx.MxRecords == null || mx.MxRecords.Count == 0) {
            yield break;
        }

        foreach (var record in mx.MxRecords) {
            if (string.IsNullOrWhiteSpace(record)) {
                continue;
            }
            var parts = record.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2) {
                continue;
            }
            var host = parts[1].Trim().Trim('.');
            if (string.IsNullOrWhiteSpace(host)) {
                continue;
            }
            yield return host;
        }
    }

    private static void EvaluateNs(string domain, NSAnalysis ns, DesiredStateNsPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.RequireRecord == true && !ns.NsRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.NsMissingRecord,
                Message = "Desired state requires NS records, but none were found."
            });
            return;
        }

        if (!ns.NsRecordExists) {
            return;
        }

        if (desired.RequireAtLeastTwo == true && !ns.AtLeastTwoRecords) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.NsTooFewRecords,
                Message = "Desired state requires at least two NS records."
            });
        }

        if (desired.DisallowDuplicates == true && ns.HasDuplicates) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.NsDuplicatesNotAllowed,
                Message = "Desired state does not allow duplicate NS records."
            });
        }

        if (desired.RequireAllHaveAOrAaaa == true && !ns.AllHaveAOrAaaa) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.NsMissingAddress,
                Message = "Desired state requires all NS hostnames to have A/AAAA records."
            });
        }

        if (desired.DisallowCnameTargets == true && ns.PointsToCname) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.NsCnameTargetNotAllowed,
                Message = "Desired state does not allow NS hostnames that point to CNAMEs."
            });
        }

        if (desired.RequireDiversity == true && !ns.HasDiverseLocations) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.NsDiversityRequired,
                Message = "Desired state requires authoritative name servers to be diverse across networks/providers."
            });
        }

        if (desired.MinAsnDiversity.HasValue && ns.AsnDistinctCount < desired.MinAsnDiversity.Value) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.NsAsnDiversityTooLow,
                Message = $"Desired state requires NS ASN diversity >= {desired.MinAsnDiversity.Value}, but found {ns.AsnDistinctCount}."
            });
        }

        if (desired.AllowedHostSuffixes != null && desired.AllowedHostSuffixes.Length > 0 && ns.NsRecords != null && ns.NsRecords.Count > 0) {
            var suffixes = desired.AllowedHostSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (suffixes.Length > 0) {
                foreach (var host in ns.NsRecords) {
                    if (string.IsNullOrWhiteSpace(host)) {
                        continue;
                    }
                    var normalized = host.Trim().Trim('.');
                    if (normalized.Length == 0) {
                        continue;
                    }
                    var ok = suffixes.Any(s => normalized.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.NsHostNotAllowed,
                            Message = $"Desired state requires NS hosts to end with [{string.Join(", ", suffixes)}], but found '{normalized}'."
                        });
                    }
                }
            }
        }
    }

    private static void EvaluateCaa(string domain, CAAAnalysis caa, DesiredStateCaaPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        var hasConstraints =
            (desired.AllowedCertificateIssuers != null && desired.AllowedCertificateIssuers.Length > 0) ||
            (desired.AllowedWildcardIssuers != null && desired.AllowedWildcardIssuers.Length > 0) ||
            (desired.RequireIodef == true) ||
            (desired.AllowedIodefDomainSuffixes != null && desired.AllowedIodefDomainSuffixes.Length > 0);

        var requireRecord = desired.RequireRecord == true || hasConstraints;
        var hasRecord = caa.AnalysisResults != null && caa.AnalysisResults.Count > 0;

        if (requireRecord && !hasRecord) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.CaaMissingRecord,
                Message = "Desired state requires a CAA record, but none was found."
            });
            return;
        }

        if (!hasRecord) {
            return;
        }

        if (desired.RequireValid == true && !caa.Valid) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.CaaPolicyInvalid,
                Message = "Desired state requires valid CAA records, but invalid/conflicting records were detected."
            });
        }

        if (desired.AllowedCertificateIssuers != null && desired.AllowedCertificateIssuers.Length > 0 && caa.CanIssueCertificatesForDomain != null) {
            var allowed = new HashSet<string>(desired.AllowedCertificateIssuers.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i.Trim()), StringComparer.OrdinalIgnoreCase);
            if (allowed.Count > 0) {
                foreach (var issuer in caa.CanIssueCertificatesForDomain) {
                    if (string.IsNullOrWhiteSpace(issuer)) {
                        continue;
                    }
                    if (!allowed.Contains(issuer.Trim())) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.CaaIssuerNotAllowed,
                            Message = $"Desired state requires CAA issue issuer in [{string.Join(", ", allowed)}], but found '{issuer}'."
                        });
                    }
                }
            }
        }

        if (desired.AllowedWildcardIssuers != null && desired.AllowedWildcardIssuers.Length > 0 && caa.CanIssueWildcardCertificatesForDomain != null) {
            var allowed = new HashSet<string>(desired.AllowedWildcardIssuers.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i.Trim()), StringComparer.OrdinalIgnoreCase);
            if (allowed.Count > 0) {
                foreach (var issuer in caa.CanIssueWildcardCertificatesForDomain) {
                    if (string.IsNullOrWhiteSpace(issuer)) {
                        continue;
                    }
                    if (!allowed.Contains(issuer.Trim())) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.CaaWildcardIssuerNotAllowed,
                            Message = $"Desired state requires CAA issuewild issuer in [{string.Join(", ", allowed)}], but found '{issuer}'."
                        });
                    }
                }
            }
        }

        if (desired.RequireIodef == true && (caa.ReportViolationEmail == null || caa.ReportViolationEmail.Count == 0)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.CaaIodefMissing,
                Message = "Desired state requires a CAA iodef reporting endpoint, but none was configured."
            });
        }

        if (desired.AllowedIodefDomainSuffixes != null && desired.AllowedIodefDomainSuffixes.Length > 0 && caa.ReportViolationEmail != null && caa.ReportViolationEmail.Count > 0) {
            var suffixes = desired.AllowedIodefDomainSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (suffixes.Length > 0) {
                foreach (var reportDomain in EnumerateCaaReportDomains(caa)) {
                    var ok = suffixes.Any(s => reportDomain.EndsWith(s, StringComparison.OrdinalIgnoreCase));
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Error,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.CaaIodefDomainNotAllowed,
                            Message = $"Desired state requires CAA iodef domains to end with [{string.Join(", ", suffixes)}], but found '{reportDomain}'."
                        });
                    }
                }
            }
        }
    }

    private static void EvaluateDnssec(string domain, DnsSecAnalysis dnssec, DesiredStateDnssecPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        if (desired.RequireChainValid == true && !dnssec.ChainValid) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnssecChainInvalid,
                Message = "Desired state requires a valid DNSSEC chain, but validation did not succeed."
            });
        }

        if (desired.MinRrsigDaysRemaining.HasValue && dnssec.Rrsigs != null && dnssec.Rrsigs.Count > 0) {
            var thresholdDays = desired.MinRrsigDaysRemaining.Value;
            if (thresholdDays < 0) {
                thresholdDays = 0;
            }

            var minDaysRemaining = dnssec.Rrsigs.Min(r => r.DaysRemaining);
            if (minDaysRemaining < thresholdDays) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DnssecRrsigExpiringSoon,
                    Message = $"Desired state requires DNSSEC signatures to have at least {thresholdDays} days remaining, but the minimum is {minDaysRemaining:F1} days."
                });
            }
        }
    }

    private static void EvaluateSoa(string domain, SOAAnalysis soa, DesiredStateSoaPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        if (desired.RequireRecord == true && !soa.RecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SoaMissingRecord,
                Message = "Desired state requires an SOA record, but none was found."
            });
            return;
        }

        if (!soa.RecordExists) {
            return;
        }

        if (desired.RequireSerialFormat == true && !soa.SerialFormatValid) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SoaSerialFormatInvalid,
                Message = "Desired state requires the SOA serial to use YYYYMMDDnn format, but it was not in that format."
            });
        }

        AddSoaRangeAssessment(domain, sink, "Refresh", soa.Refresh, desired.MinRefresh, desired.MaxRefresh, DesiredStateCodes.SoaRefreshOutOfRange);
        AddSoaRangeAssessment(domain, sink, "Retry", soa.Retry, desired.MinRetry, desired.MaxRetry, DesiredStateCodes.SoaRetryOutOfRange);
        AddSoaRangeAssessment(domain, sink, "Expire", soa.Expire, desired.MinExpire, desired.MaxExpire, DesiredStateCodes.SoaExpireOutOfRange);
        AddSoaRangeAssessment(domain, sink, "Minimum", soa.Minimum, desired.MinMinimum, desired.MaxMinimum, DesiredStateCodes.SoaMinimumOutOfRange);
    }

    private static void AddSoaRangeAssessment(string domain, DesiredStateAnalysis sink, string fieldName, int actual, int? min, int? max, string code) {
        if (sink == null) {
            return;
        }
        if (!min.HasValue && !max.HasValue) {
            return;
        }
        if (actual <= 0) {
            return;
        }

        var tooLow = min.HasValue && actual < min.Value;
        var tooHigh = max.HasValue && actual > max.Value;
        if (!tooLow && !tooHigh) {
            return;
        }

        var range = $"{(min.HasValue ? min.Value.ToString() : "-inf")}..{(max.HasValue ? max.Value.ToString() : "+inf")}";
        sink.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning,
            Category = "DesiredState",
            Target = domain,
            Code = code,
            Message = $"Desired state requires SOA {fieldName} to be within {range} seconds, but found {actual}."
        });
    }

    private static void EvaluateDane(string domain, DANEAnalysis dane, DesiredStateDanePolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        var hasAnyRecords = dane.NumberOfRecords > 0;
        var requiredServices = desired.RequiredServices != null && desired.RequiredServices.Length > 0
            ? desired.RequiredServices.Distinct().ToArray()
            : Array.Empty<ServiceType>();

        if (requiredServices.Length == 0) {
            if (desired.RequireRecord == true && !hasAnyRecords) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DaneMissingRecord,
                    Message = "Desired state requires TLSA (DANE) records, but none were found."
                });
                return;
            }
        } else if (desired.RequireRecord == true) {
            foreach (var service in requiredServices) {
                var hasServiceRecord = dane.AnalysisResults != null && dane.AnalysisResults.Any(r => r.ServiceType == service);
                if (!hasServiceRecord) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Error,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.DaneServiceMissingRecord,
                        Message = $"Desired state requires TLSA (DANE) records for {service}, but none were found."
                    });
                }
            }
        }

        if (!hasAnyRecords) {
            return;
        }

        if (desired.DisallowDuplicates == true && dane.HasDuplicateRecords) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DaneDuplicateNotAllowed,
                Message = "Desired state does not allow duplicate TLSA (DANE) records, but duplicates were detected."
            });
        }

        if (desired.RequireValidRecords == true && dane.HasInvalidRecords) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DaneInvalidRecords,
                Message = "Desired state requires valid TLSA (DANE) records, but invalid records were detected."
            });
        }

        if (dane.AnalysisResults == null || dane.AnalysisResults.Count == 0) {
            return;
        }

        if (requiredServices.Length > 0) {
            foreach (var service in requiredServices) {
                var records = dane.AnalysisResults.Where(r => r.ServiceType == service).ToArray();
                if (records.Length == 0) {
                    continue;
                }

                if (service == ServiceType.SMTP && desired.RequireRecommendedForSmtp == true) {
                    var ok = records.Any(r => r.ValidDANERecord && r.IsValidChoiceForSmtp);
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Warning,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.DaneSmtpRecommendedMissing,
                            Message = "Desired state requires a recommended TLSA configuration for SMTP (3 1 1), but none was found."
                        });
                    }
                }

                if (service == ServiceType.HTTPS && desired.RequireRecommendedForHttps == true) {
                    var ok = records.Any(r => r.ValidDANERecord && r.IsValidChoiceForHttps);
                    if (!ok) {
                        sink.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Warning,
                            Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.DaneHttpsRecommendedMissing,
                            Message = "Desired state requires a recommended TLSA configuration for HTTPS (3 1 1), but none was found."
                        });
                    }
                }
            }
        } else {
            if (desired.RequireRecommendedForSmtp == true) {
                var ok = dane.AnalysisResults.Any(r => r.ServiceType == ServiceType.SMTP && r.ValidDANERecord && r.IsValidChoiceForSmtp);
                if (!ok) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.DaneSmtpRecommendedMissing,
                        Message = "Desired state requires a recommended TLSA configuration for SMTP (3 1 1), but none was found."
                    });
                }
            }

            if (desired.RequireRecommendedForHttps == true) {
                var ok = dane.AnalysisResults.Any(r => r.ServiceType == ServiceType.HTTPS && r.ValidDANERecord && r.IsValidChoiceForHttps);
                if (!ok) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.DaneHttpsRecommendedMissing,
                        Message = "Desired state requires a recommended TLSA configuration for HTTPS (3 1 1), but none was found."
                    });
                }
            }
        }
    }

    private static void EvaluateDelegation(string domain, NSAnalysis ns, DesiredStateDelegationPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        if (desired.RequireMatchesParent == true && !ns.DelegationMatches) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DelegationMismatch,
                Message = "Desired state requires parent delegation to match the child NS set, but it did not match."
            });
        }

        if (desired.RequireGlueComplete == true && !ns.GlueRecordsComplete) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DelegationGlueIncomplete,
                Message = "Desired state requires glue records to be complete for in-bailiwick name servers, but some glue was missing."
            });
        }

        if (desired.RequireGlueConsistent == true && !ns.GlueRecordsConsistent) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DelegationGlueInconsistent,
                Message = "Desired state requires parent glue records to match child A/AAAA records, but inconsistencies were detected."
            });
        }
    }

    private static void EvaluateZoneTransfer(string domain, ZoneTransferAnalysis zoneTransfer, DesiredStateZoneTransferPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        if (desired.DisallowUnauthenticatedAxfr != true) {
            return;
        }

        if (zoneTransfer.ServerResults == null || zoneTransfer.ServerResults.Count == 0) {
            return;
        }

        foreach (var kvp in zoneTransfer.ServerResults) {
            if (!kvp.Value) {
                continue;
            }

            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ZoneTransferAllowed,
                Message = $"Desired state disallows unauthenticated AXFR, but zone transfer was allowed on '{kvp.Key}'."
            });
        }
    }

    private static void EvaluateWildcardDns(string domain, WildcardDnsAnalysis wildcard, DesiredStateWildcardDnsPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        if (!desired.ExpectedCatchAll.HasValue) {
            return;
        }

        var expected = desired.ExpectedCatchAll.Value;
        if (expected && !wildcard.CatchAll) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.WildcardCatchAllRequired,
                Message = "Desired state requires wildcard DNS (catch-all), but it was not detected."
            });
        }

        if (!expected && wildcard.CatchAll) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.WildcardCatchAllNotAllowed,
                Message = "Desired state disallows wildcard DNS (catch-all), but it was detected."
            });
        }
    }

    private static IEnumerable<string> EnumerateCaaReportDomains(CAAAnalysis caa) {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (caa == null || caa.ReportViolationEmail == null || caa.ReportViolationEmail.Count == 0) return set;

        foreach (var value in caa.ReportViolationEmail) {
            if (string.IsNullOrWhiteSpace(value)) {
                continue;
            }

            if (value.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) {
                var m = value.Substring("mailto:".Length).Trim();
                var at = m.IndexOf('@');
                if (at > -1 && at < m.Length - 1) {
                    var dom = m.Substring(at + 1).Trim().Trim('.');
                    if (dom.Length > 0) {
                        set.Add(dom);
                    }
                }
                continue;
            }

            var host = TryGetHost(value);
            if (!string.IsNullOrWhiteSpace(host)) {
                set.Add(host);
            }
        }

        return set;
    }

    private static string? TryGetHost(string? uriString) {
        if (string.IsNullOrWhiteSpace(uriString)) return null;
        if (!Uri.TryCreate(uriString, UriKind.Absolute, out var uri)) return null;
        if (string.IsNullOrWhiteSpace(uri.Host)) return null;
        return uri.Host.Trim().Trim('.');
    }
}
