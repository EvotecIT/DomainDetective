using DomainDetective.Definitions;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    private static void EvaluateDanglingCname(string domain, DanglingCnameAnalysis cname, DesiredStateDanglingCnamePolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;

        if (desired.DisallowUnclaimedService == true && cname.UnclaimedService) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DanglingCnameUnclaimedService,
                Message = $"Desired state does not allow unclaimed-service dangling CNAMEs, but '{(cname.Target ?? string.Empty)}' does not resolve."
            });
            return;
        }

        if (desired.DisallowDangling == true && cname.IsDangling) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DanglingCnameDangling,
                Message = $"Desired state does not allow dangling CNAMEs, but '{(cname.Target ?? string.Empty)}' does not resolve."
            });
        }
    }

    private static void EvaluateDnsHealth(string domain, DnsHealthAnalysis dnsHealth, DesiredStateDnsHealthPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) {
            return;
        }

        if (dnsHealth == null) {
            return;
        }

        var hasConstraints =
            desired.RequireServersResponsive == true ||
            desired.RequireSoaSerialConsistent == true ||
            desired.RequireApexAddressesConsistent == true;

        var requireAtLeastOne = desired.RequireAtLeastOneResult == true || hasConstraints;
        var hasResults = (dnsHealth.SoaSerialByServer != null && dnsHealth.SoaSerialByServer.Count > 0) ||
            (dnsHealth.ApexAddressesByServer != null && dnsHealth.ApexAddressesByServer.Count > 0);

        if (requireAtLeastOne && !hasResults) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnsHealthNoResults,
                Message = "Desired state requires DNS health results to be analyzed, but none were produced."
            });
            return;
        }

        if (desired.RequireServersResponsive == true && !dnsHealth.ServersResponsive) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnsHealthServersUnresponsive,
                Message = "Desired state requires all authoritative servers to respond to DNS health queries, but some did not."
            });
        }

        if (desired.RequireSoaSerialConsistent == true && !dnsHealth.SoaSerialConsistent) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnsHealthSoaSerialInconsistent,
                Message = "Desired state requires SOA serial to be consistent across authoritative servers, but it differed."
            });
        }

        if (desired.RequireApexAddressesConsistent == true && !dnsHealth.ApexAddressesConsistent) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnsHealthApexInconsistent,
                Message = "Desired state requires apex A/AAAA answers to be consistent across authoritative servers, but they differed."
            });
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
}

