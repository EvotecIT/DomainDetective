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

        if (desired.RequireSingleRecord == true && dmarc.MultipleRecords) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcMultipleRecordsNotAllowed,
                Message = "Desired state requires exactly one DMARC record, but multiple records were detected."
            });
        }

        if (desired.RequireValidRecord == true) {
            var problems = new List<string>();
            if (!dmarc.StartsCorrectly) problems.Add("missing v=DMARC1");
            if (!dmarc.HasMandatoryTags) problems.Add("missing mandatory tags");
            if (!dmarc.IsPolicyValid) problems.Add("invalid policy tag");
            if (!dmarc.IsPctValid) problems.Add("invalid pct value");
            if (dmarc.InvalidReportUri) problems.Add("invalid report URI(s)");

            if (problems.Count > 0) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DmarcInvalidRecord,
                    Message = $"Desired state requires a valid DMARC record, but the record failed validation: {string.Join("; ", problems)}."
                });
            }
        }

        if (desired.DisallowRecordOver255 == true && dmarc.ExceedsCharacterLimit) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcRecordTooLong,
                Message = "Desired state disallows DMARC records longer than 255 characters, but the record exceeded 255 characters."
            });
        }

        if (desired.DisallowUnknownTags == true && dmarc.UnknownTags != null && dmarc.UnknownTags.Count > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcUnknownTagsNotAllowed,
                Message = $"Desired state disallows unknown DMARC tags, but found: {string.Join(", ", dmarc.UnknownTags)}."
            });
        }

        if (desired.DisallowDeprecatedTags == true && dmarc.DeprecatedTags != null && dmarc.DeprecatedTags.Count > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcDeprecatedTagsNotAllowed,
                Message = $"Desired state disallows deprecated DMARC tags, but found: {string.Join(", ", dmarc.DeprecatedTags)}."
            });
        }

        if (desired.DisallowRuf == true) {
            var rufCount = (dmarc.MailtoRuf?.Count ?? 0) + (dmarc.HttpRuf?.Count ?? 0);
            if (rufCount > 0) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DmarcRufNotAllowed,
                    Message = "Desired state disallows DMARC forensic reporting (ruf=), but one or more ruf URIs were configured."
                });
            }
        }

        if (desired.DisallowHttpRuf == true && (dmarc.HttpRuf?.Count ?? 0) > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcHttpRufNotAllowed,
                Message = "Desired state disallows HTTPS endpoints in DMARC forensic reporting (ruf=), but one or more HTTPS ruf URIs were configured."
            });
        }

        if (desired.DisallowWeakPolicy == true && dmarc.WeakPolicy) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcWeakPolicyNotAllowed,
                Message = "Desired state disallows weak DMARC policy (p=none or sp=none)."
            });
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

        if (desired.RequireMailtoRua == true && (dmarc.MailtoRua?.Count ?? 0) == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcMailtoRuaMissing,
                Message = "Desired state requires at least one mailto: DMARC aggregate reporting address (rua=mailto:...), but none was configured."
            });
        }

        if (desired.DisallowHttpRua == true && (dmarc.HttpRua?.Count ?? 0) > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DmarcHttpRuaNotAllowed,
                Message = "Desired state disallows HTTPS endpoints in DMARC aggregate reporting (rua=), but one or more HTTPS rua URIs were configured."
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
                    if (string.IsNullOrWhiteSpace(reportDomain)) continue;
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

        if (desired.DisallowCname == true && spf.IsCnameResolved) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfCnameNotAllowed,
                Message = "Desired state disallows SPF records resolved through a CNAME alias, but SPF was resolved via CNAME."
            });
        }

        if (desired.RequireValidRecord == true) {
            var problems = new List<string>();
            if (!spf.StartsCorrectly) problems.Add("missing v=spf1");
            if (spf.InvalidIpSyntax) problems.Add("invalid IP syntax");
            if (spf.HasNullLookups) problems.Add("null/empty lookup token");
            if (spf.MultipleAllMechanisms) problems.Add("multiple all mechanisms");
            if (spf.ContainsCharactersAfterAll) problems.Add("characters after all mechanism");
            if (spf.ExceedsCharacterLimit) problems.Add("TXT chunk > 255 characters");
            if (spf.ExceedsTotalCharacterLimit) problems.Add("total SPF length > 512 characters");
            if (spf.PermError) problems.Add("PermError");

            if (problems.Count > 0) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.SpfInvalidRecord,
                    Message = $"Desired state requires a valid SPF record, but the record failed validation: {string.Join("; ", problems)}."
                });
            }
        }

        if (desired.RequireSingleRecord == true && spf.MultipleSpfRecords) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfMultipleRecordsNotAllowed,
                Message = "Desired state requires exactly one SPF record, but multiple records were detected."
            });
        }

        if (desired.RequireEffectiveSpfSends == true && !spf.EffectiveSpfSends) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfEffectiveSendingRequired,
                Message = "Desired state requires SPF to effectively authorize outbound senders, but no effective authorization was detected."
            });
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

        if (desired.RequireAllMechanism == true && string.IsNullOrWhiteSpace(spf.AllMechanism)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfAllMechanismMissing,
                Message = "Desired state requires an SPF all mechanism (e.g., -all, ~all), but none was found."
            });
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

        if (desired.DisallowExp == true && spf.HasExp) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfExpNotAllowed,
                Message = "Desired state disallows SPF exp= (explanation) modifier, but it was present."
            });
        }

        if (desired.DisallowPermError == true && spf.PermError) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.SpfPermErrorNotAllowed,
                Message = "Desired state disallows SPF PermError results, but SPF evaluation produced PermError."
            });
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
        if (desired.RequireStartsCorrectly == true && !analysis.StartsCorrectly) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimStartsInvalid,
                Message = $"Desired state requires DKIM records to start with v=DKIM1 for selector '{selector}', but it did not."
            });
        }

        if (desired.RequirePublicKey == true && !analysis.PublicKeyExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimPublicKeyMissing,
                Message = $"Desired state requires DKIM selector '{selector}' to publish a public key (p=), but it was missing."
            });
        }

        if (desired.RequireValidPublicKey == true && !analysis.ValidPublicKey) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimPublicKeyInvalid,
                Message = $"Desired state requires DKIM selector '{selector}' to publish a valid public key (p=), but the key could not be validated."
            });
        }

        if (desired.RequireValidKeyType == true && !analysis.ValidKeyType) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimKeyTypeInvalid,
                Message = $"Desired state requires DKIM selector '{selector}' to use a recognized key type (k=rsa/ed25519), but it did not."
            });
        }

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

        if (desired.DisallowWeakKeys == true && analysis.WeakKey) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimWeakKeyNotAllowed,
                Message = $"Desired state disallows weak DKIM keys (< 2048 bits) for selector '{selector}', but a weak key was detected."
            });
        }

        if (desired.MaxKeyAgeDays.HasValue && desired.MaxKeyAgeDays.Value > 0 && analysis.CreationDate.HasValue) {
            if (analysis.KeyAgeDays > desired.MaxKeyAgeDays.Value) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DkimKeyTooOld,
                    Message = $"Desired state requires DKIM key age <= {desired.MaxKeyAgeDays.Value} days for selector '{selector}', but found {analysis.KeyAgeDays} days."
                });
            }
        }

        if (desired.DisallowDeprecatedTags == true && analysis.DeprecatedTags != null && analysis.DeprecatedTags.Count > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimDeprecatedTagsNotAllowed,
                Message = $"Desired state disallows deprecated DKIM tags/values for selector '{selector}', but found: {string.Join(", ", analysis.DeprecatedTags)}."
            });
        }

        if (desired.DisallowInvalidFlags == true && !analysis.ValidFlags) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimFlagsInvalid,
                Message = $"Desired state disallows invalid DKIM flags for selector '{selector}', but invalid flags were present."
            });
        }

        if (desired.DisallowUnknownCanonicalizationModes == true && analysis.UnknownCanonicalizationModes != null && analysis.UnknownCanonicalizationModes.Count > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimCanonicalizationUnknownNotAllowed,
                Message = $"Desired state disallows unknown DKIM canonicalization modes for selector '{selector}', but found: {string.Join(", ", analysis.UnknownCanonicalizationModes)}."
            });
        }

        if (desired.DisallowInvalidCanonicalization == true && !string.IsNullOrWhiteSpace(analysis.Canonicalization) && !analysis.ValidCanonicalization) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DkimCanonicalizationInvalid,
                Message = $"Desired state disallows invalid DKIM canonicalization for selector '{selector}', but found '{analysis.Canonicalization}'."
            });
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
