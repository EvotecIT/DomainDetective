using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
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
}

