using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
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

    private static void EvaluateDnsbl(string domain, DNSBLAnalysis dnsbl, DesiredStateDnsblPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        if (dnsbl == null) {
            return;
        }

        var records = dnsbl.AllResults ?? new List<DNSBLRecord>();
        if (desired.RequireAtLeastOneResult == true && records.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnsblNoResults,
                Message = "Desired state requires DNSBL results to be analyzed, but none were produced."
            });
            return;
        }

        if (desired.DisallowListings != true) {
            return;
        }

        if (records.Count == 0) {
            return;
        }

        var ignored = desired.IgnoredBlacklists != null && desired.IgnoredBlacklists.Length > 0
            ? new HashSet<string>(
                desired.IgnoredBlacklists
                    .Where(s => !string.IsNullOrWhiteSpace(s))
                    .Select(s => s.Trim().Trim('.')),
                StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        HashSet<DnsblQueryKind>? includeKinds = null;
        if (desired.IncludeQueryKinds != null && desired.IncludeQueryKinds.Length > 0) {
            includeKinds = new HashSet<DnsblQueryKind>(desired.IncludeQueryKinds.Distinct());
        }

        HashSet<DnsblIpSource>? includeSources = null;
        if (desired.IncludeIpSources != null && desired.IncludeIpSources.Length > 0) {
            includeSources = new HashSet<DnsblIpSource>(desired.IncludeIpSources.Distinct());
        }

        foreach (var r in records) {
            if (r == null) continue;
            if (!r.IsBlackListed) continue;

            var blacklist = (r.BlackList ?? string.Empty).Trim().Trim('.');
            if (blacklist.Length == 0) continue;

            if (ignored.Count > 0 && ignored.Contains(blacklist)) {
                continue;
            }

            if (includeKinds != null && includeKinds.Count > 0 && !includeKinds.Contains(r.QueryKind)) {
                continue;
            }

            if (includeSources != null && includeSources.Count > 0 && r.IpSource.HasValue && !includeSources.Contains(r.IpSource.Value)) {
                continue;
            }

            var subject = r.IpAddress ?? r.SourceHost ?? r.Query ?? domain;
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnsblListed,
                Message = $"Desired state does not allow DNSBL listings, but '{subject}' is listed on '{blacklist}'."
            });
        }
    }

    private static IEnumerable<string> EnumerateCaaReportDomains(CAAAnalysis? caa) {
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
            // On net472 reference assemblies, string.IsNullOrWhiteSpace may not be nullable-annotated,
            // so we guard explicitly to avoid CS8602.
            if (host == null) {
                continue;
            }

            var normalized = host.Trim().Trim('.');
            if (normalized.Length > 0) {
                set.Add(normalized);
            }
        }

        return set;
    }
}
