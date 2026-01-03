using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    private static void EvaluateReverseDns(string domain, ReverseDnsAnalysis reverseDns, DesiredStateReverseDnsPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        var hasConstraints =
            desired.RequirePtrPresent == true ||
            desired.RequirePtrMatchesExpectedHost == true ||
            desired.RequireForwardConfirmed == true ||
            (desired.AllowedPtrSuffixes != null && desired.AllowedPtrSuffixes.Length > 0);

        var requireAtLeastOne = desired.RequireAtLeastOneResult == true || hasConstraints;
        var results = reverseDns?.Results;
        if (results == null || results.Count == 0) {
            if (requireAtLeastOne) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.ReverseDnsNoResults,
                    Message = "Desired state requires reverse DNS results to be analyzed, but none were produced."
                });
            }
            return;
        }

        var suffixes = desired.AllowedPtrSuffixes != null && desired.AllowedPtrSuffixes.Length > 0
            ? desired.AllowedPtrSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray()
            : Array.Empty<string>();

        foreach (var res in results) {
            if (res == null) continue;

            var ip = res.IpAddress?.Trim() ?? string.Empty;
            var expected = (res.ExpectedHost ?? string.Empty).Trim().Trim('.').ToLowerInvariant();
            var ptrs = res.PtrRecords ?? new List<string>();

            if (desired.RequirePtrPresent == true && ptrs.Count == 0) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.ReverseDnsPtrMissing,
                    Message = $"Desired state requires PTR records for IP '{ip}', but none were found."
                });
            }

            if (desired.RequirePtrMatchesExpectedHost == true) {
                var match = expected.Length > 0 && ptrs.Any(p => string.Equals((p ?? string.Empty).Trim().Trim('.'), expected, StringComparison.OrdinalIgnoreCase));
                if (!match) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.ReverseDnsPtrExpectedMismatch,
                        Message = $"Desired state requires PTR to match expected host '{expected}' for IP '{ip}', but it did not."
                    });
                }
            }

            if (suffixes.Length > 0 && ptrs.Count > 0) {
                var ok = ptrs.Any(p => suffixes.Any(s => (p ?? string.Empty).Trim().Trim('.').EndsWith(s, StringComparison.OrdinalIgnoreCase)));
                if (!ok) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.ReverseDnsPtrSuffixNotAllowed,
                        Message = $"Desired state requires PTR hostnames for IP '{ip}' to end with [{string.Join(", ", suffixes)}], but none matched."
                    });
                }
            }

            if (desired.RequireForwardConfirmed == true && !res.FcrDnsValid) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.ReverseDnsForwardNotConfirmed,
                    Message = $"Desired state requires forward-confirmed reverse DNS (FCrDNS) for IP '{ip}', but it was not confirmed."
                });
            }
        }
    }

    private static void EvaluateFcrDns(string domain, FCrDnsAnalysis fcrDns, DesiredStateFcrDnsPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        var hasConstraints = desired.RequireAllForwardConfirmed == true;
        var requireAtLeastOne = desired.RequireAtLeastOneResult == true || hasConstraints;
        var results = fcrDns?.Results;
        if (results == null || results.Count == 0) {
            if (requireAtLeastOne) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.FcrDnsNoResults,
                    Message = "Desired state requires FCrDNS results to be analyzed, but none were produced."
                });
            }
            return;
        }

        if (desired.RequireAllForwardConfirmed == true) {
            foreach (var res in results) {
                if (res == null) continue;
                if (res.ForwardConfirmed) continue;

                var ip = res.IpAddress?.Trim() ?? string.Empty;
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.FcrDnsForwardMismatch,
                    Message = $"Desired state requires forward-confirmed reverse DNS (FCrDNS) for IP '{ip}', but it was not confirmed."
                });
            }
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

    private static void EvaluateTtl(string domain, DnsTtlAnalysis ttl, DesiredStateTtlPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        AddTtlRangeAssessments(domain, sink, "A", ttl.ATtls, desired.MinASeconds, desired.MaxASeconds, DesiredStateCodes.TtlAOutOfRange);
        AddTtlRangeAssessments(domain, sink, "AAAA", ttl.AaaaTtls, desired.MinAaaaSeconds, desired.MaxAaaaSeconds, DesiredStateCodes.TtlAaaaOutOfRange);
        AddTtlRangeAssessments(domain, sink, "MX", ttl.MxTtls, desired.MinMxSeconds, desired.MaxMxSeconds, DesiredStateCodes.TtlMxOutOfRange);
        AddTtlRangeAssessments(domain, sink, "NS", ttl.NsTtls, desired.MinNsSeconds, desired.MaxNsSeconds, DesiredStateCodes.TtlNsOutOfRange);
        AddTtlRangeAssessment(domain, sink, "SOA", ttl.SoaTtl, desired.MinSoaSeconds, desired.MaxSoaSeconds, DesiredStateCodes.TtlSoaOutOfRange);

        AddTtlRangeAssessments(domain, sink, "TXT(SPF)", ttl.SpfTxtTtls, desired.MinSpfTxtSeconds, desired.MaxSpfTxtSeconds, DesiredStateCodes.TtlSpfTxtOutOfRange);
        AddTtlRangeAssessments(domain, sink, "TXT(DMARC)", ttl.DmarcTxtTtls, desired.MinDmarcTxtSeconds, desired.MaxDmarcTxtSeconds, DesiredStateCodes.TtlDmarcTxtOutOfRange);
        AddTtlRangeAssessments(domain, sink, "TXT(MTA-STS)", ttl.MtastsTxtTtls, desired.MinMtastsTxtSeconds, desired.MaxMtastsTxtSeconds, DesiredStateCodes.TtlMtastsTxtOutOfRange);
        AddTtlRangeAssessments(domain, sink, "TXT(TLS-RPT)", ttl.TlsRptTxtTtls, desired.MinTlsRptTxtSeconds, desired.MaxTlsRptTxtSeconds, DesiredStateCodes.TtlTlsRptTxtOutOfRange);

        if (desired.MinDkimSelectorTxtSeconds.HasValue || desired.MaxDkimSelectorTxtSeconds.HasValue) {
            if (ttl.DkimTxtTtls != null && ttl.DkimTxtTtls.Count > 0) {
                foreach (var kvp in ttl.DkimTxtTtls) {
                    AddTtlRangeAssessments(domain, sink, $"TXT(DKIM:{kvp.Key})", kvp.Value, desired.MinDkimSelectorTxtSeconds, desired.MaxDkimSelectorTxtSeconds, DesiredStateCodes.TtlDkimTxtOutOfRange);
                }
            }
        }

        if (desired.RequireAUniformAcrossNs == true && !IsUniform(ttl.ServerTtlA)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TtlAUniformityRequired,
                Message = "Desired state requires A TTL to be uniform across authoritative name servers, but it was not uniform."
            });
        }

        if (desired.RequireAaaaUniformAcrossNs == true && !IsUniform(ttl.ServerTtlAaaa)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TtlAaaaUniformityRequired,
                Message = "Desired state requires AAAA TTL to be uniform across authoritative name servers, but it was not uniform."
            });
        }

        if (desired.RequireNsUniformAcrossNs == true && !IsUniform(ttl.ServerTtlNs)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TtlNsUniformityRequired,
                Message = "Desired state requires NS TTL to be uniform across authoritative name servers, but it was not uniform."
            });
        }

        if (desired.RequireCnameUniformAcrossNs == true && !IsUniform(ttl.ServerTtlCname)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TtlCnameUniformityRequired,
                Message = "Desired state requires CNAME TTL to be uniform across authoritative name servers, but it was not uniform."
            });
        }

        if (desired.RequireSpfTxtUniformAcrossNs == true && !IsUniform(ttl.ServerTtlTxtSpf)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TtlSpfTxtUniformityRequired,
                Message = "Desired state requires SPF TXT TTL to be uniform across authoritative name servers, but it was not uniform."
            });
        }

        if (desired.RequireDmarcTxtUniformAcrossNs == true && !IsUniform(ttl.ServerTtlTxtDmarc)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.TtlDmarcTxtUniformityRequired,
                Message = "Desired state requires DMARC TXT TTL to be uniform across authoritative name servers, but it was not uniform."
            });
        }

        if (desired.RequireDkimTxtUniformAcrossNs == true && ttl.ServerTtlTxtPerName != null && ttl.ServerTtlTxtPerName.Count > 0) {
            foreach (var kvp in ttl.ServerTtlTxtPerName) {
                if (!IsUniform(kvp.Value)) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.TtlDkimTxtUniformityRequired,
                        Message = $"Desired state requires DKIM TXT TTL to be uniform across authoritative name servers for {kvp.Key}, but it was not uniform."
                    });
                }
            }
        }
    }

    private static void AddTtlRangeAssessment(string domain, DesiredStateAnalysis sink, string recordType, int ttlSeconds, int? minSeconds, int? maxSeconds, string code) {
        if (ttlSeconds <= 0) {
            return;
        }
        AddTtlRangeAssessments(domain, sink, recordType, new[] { ttlSeconds }, minSeconds, maxSeconds, code);
    }

    private static void AddTtlRangeAssessments(string domain, DesiredStateAnalysis sink, string recordType, IEnumerable<int> ttlSeconds, int? minSeconds, int? maxSeconds, string code) {
        if (!minSeconds.HasValue && !maxSeconds.HasValue) {
            return;
        }

        var values = (ttlSeconds ?? Array.Empty<int>()).Where(t => t > 0).ToArray();
        if (values.Length == 0) {
            return;
        }

        var below = minSeconds.HasValue ? values.Where(t => t < minSeconds.Value).ToArray() : Array.Empty<int>();
        var above = maxSeconds.HasValue ? values.Where(t => t > maxSeconds.Value).ToArray() : Array.Empty<int>();
        if (below.Length == 0 && above.Length == 0) {
            return;
        }

        var range = $"{(minSeconds.HasValue ? minSeconds.Value.ToString() : "-inf")}..{(maxSeconds.HasValue ? maxSeconds.Value.ToString() : "+inf")}";
        var actual = $"{values.Min()}..{values.Max()}";
        sink.Assessments.Add(new Assessment {
            Severity = AssessmentSeverity.Warning,
            Category = "DesiredState",
            Target = domain,
            Code = code,
            Message = $"Desired state requires TTL for {recordType} within {range} seconds, but observed {actual} seconds."
        });
    }

    private static bool IsUniform(Dictionary<string, int?>? map) {
        if (map == null || map.Count == 0) {
            return true;
        }

        var distinct = map.Values.Where(v => v.HasValue).Select(v => v!.Value).Distinct().ToArray();
        return distinct.Length <= 1;
    }
}

