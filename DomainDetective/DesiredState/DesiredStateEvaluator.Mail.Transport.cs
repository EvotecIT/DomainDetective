using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
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
}

