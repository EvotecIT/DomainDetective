using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Definitions;
using DomainDetective.Helpers;

namespace DomainDetective.DesiredState;

public static partial class DesiredStateEvaluator {
    private static void EvaluateApexAddress(string domain, ApexAddressAnalysis analysis, DesiredStateApexAddressPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var hasAny = analysis.HasAnyAddress;
        var addressCount = (analysis.ARecords?.Count ?? 0) + (analysis.AaaaRecords?.Count ?? 0);

        if (desired.DisallowAnyAddress == true && hasAny) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressNotAllowed,
                Message = $"Desired state disallows apex A/AAAA records, but found {addressCount}."
            });
            return;
        }

        if (desired.RequireAnyAddress == true && !hasAny) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressRequiredMissing,
                Message = "Desired state requires apex A/AAAA records, but none were found."
            });
            return;
        }

        if (!hasAny) {
            return;
        }

        if (desired.DisallowPrivateAddresses == true && analysis.PrivateAddressCount > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressPrivateNotAllowed,
                Message = $"Desired state disallows private apex addresses, but found {analysis.PrivateAddressCount}."
            });
        }

        if (desired.DisallowLoopbackAddresses == true && analysis.LoopbackCount > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressLoopbackNotAllowed,
                Message = $"Desired state disallows loopback apex addresses, but found {analysis.LoopbackCount}."
            });
        }

        if (desired.DisallowLinkLocalAddresses == true && analysis.LinkLocalCount > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressLinkLocalNotAllowed,
                Message = $"Desired state disallows link-local apex addresses, but found {analysis.LinkLocalCount}."
            });
        }

        if (desired.DisallowMulticastAddresses == true && analysis.MulticastCount > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressMulticastNotAllowed,
                Message = $"Desired state disallows multicast apex addresses, but found {analysis.MulticastCount}."
            });
        }

        if (desired.DisallowDocumentationAddresses == true && analysis.DocumentationAddressCount > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressDocumentationNotAllowed,
                Message = $"Desired state disallows documentation-range apex addresses, but found {analysis.DocumentationAddressCount}."
            });
        }

        if (desired.DisallowUniqueLocalV6Addresses == true && analysis.UniqueLocalV6Count > 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressUniqueLocalNotAllowed,
                Message = $"Desired state disallows IPv6 unique-local (ULA) apex addresses, but found {analysis.UniqueLocalV6Count}."
            });
        }

        if (desired.MinDistinctSubnetCountV4.HasValue && analysis.DistinctSubnetCountV4 < desired.MinDistinctSubnetCountV4.Value) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressSubnetDiversityTooLowV4,
                Message = $"Desired state requires at least {desired.MinDistinctSubnetCountV4.Value} distinct IPv4 subnets, but found {analysis.DistinctSubnetCountV4}."
            });
        }

        if (desired.MinDistinctSubnetCountV6.HasValue && analysis.DistinctSubnetCountV6 < desired.MinDistinctSubnetCountV6.Value) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressSubnetDiversityTooLowV6,
                Message = $"Desired state requires at least {desired.MinDistinctSubnetCountV6.Value} distinct IPv6 subnets, but found {analysis.DistinctSubnetCountV6}."
            });
        }

        if (desired.RequireAllPtrPresent == true && !analysis.AllPtrPresent) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressPtrRequiredMissing,
                Message = "Desired state requires PTR records for all apex addresses, but one or more PTR records were missing."
            });
        }

        if (desired.RequireAllFcrDnsValid == true && !analysis.AllFcrDnsValid) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.ApexAddressFcrDnsRequired,
                Message = "Desired state requires forward-confirmed reverse DNS for all apex addresses, but one or more addresses were not forward-confirmed."
            });
        }
    }

    private static void EvaluateRpki(string domain, RPKIAnalysis analysis, DesiredStateRpkiPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var results = analysis.Results ?? new List<RPKIResult>();
        if (desired.RequireAtLeastOneResult == true && results.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.RpkiNoResults,
                Message = "Desired state expected RPKI analysis results, but no results were produced."
            });
            return;
        }

        if (results.Count == 0) {
            return;
        }

        var ignoredIps = new HashSet<string>(
            desired.IgnoredIpAddresses?.Where(i => !string.IsNullOrWhiteSpace(i)).Select(i => i.Trim()).ToArray() ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        var ignoredPrefixes = new HashSet<string>(
            desired.IgnoredPrefixes?.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).ToArray() ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        var ignoredAsns = new HashSet<int>(desired.IgnoredAsns ?? Array.Empty<int>());

        foreach (var r in results) {
            if (r == null) continue;

            if (!string.IsNullOrWhiteSpace(r.IpAddress) && ignoredIps.Contains(r.IpAddress)) continue;
            if (!string.IsNullOrWhiteSpace(r.Prefix) && ignoredPrefixes.Contains(r.Prefix)) continue;
            if (r.Asn != 0 && ignoredAsns.Contains(r.Asn)) continue;

            var hasLookupData = !string.IsNullOrWhiteSpace(r.Prefix) && r.Asn != 0;
            if (!hasLookupData) {
                if (desired.TreatQueryFailuresAsDrift == true) {
                    sink.Assessments.Add(new Assessment {
                        Severity = AssessmentSeverity.Warning,
                        Category = "DesiredState",
                        Target = domain,
                        Code = DesiredStateCodes.RpkiQueryFailed,
                        Message = $"RPKI validation could not be completed for IP '{r.IpAddress}'."
                    });
                }
                continue;
            }

            if (desired.DisallowInvalid == true && !r.Valid) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.RpkiInvalid,
                    Message = $"Desired state requires valid RPKI for '{r.IpAddress}' ({r.Prefix}, AS{r.Asn})."
                });
            }
        }
    }

    private static void EvaluateEdnsSupport(string domain, EdnsSupportAnalysis analysis, DesiredStateEdnsSupportPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var servers = analysis.ServerSupport ?? new Dictionary<string, EdnsSupportInfo>();
        if (desired.RequireAtLeastOneResult == true && servers.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.EdnsNoResults,
                Message = "Desired state expected EDNS support results, but no results were produced."
            });
            return;
        }

        if (servers.Count == 0) {
            return;
        }

        foreach (var kvp in servers) {
            var key = kvp.Key;
            var info = kvp.Value;

            if (desired.RequireAllServersSupported == true && !info.Supported) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.EdnsNotSupported,
                    Message = $"Desired state requires EDNS support, but '{key}' does not support EDNS."
                });
                continue;
            }

            if (!info.Supported) continue;

            if (desired.MaxUdpPayloadSize.HasValue && info.UdpPayloadSize > desired.MaxUdpPayloadSize.Value) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.EdnsUdpPayloadTooLarge,
                    Message = $"Desired state requires EDNS UDP payload <= {desired.MaxUdpPayloadSize.Value} bytes, but '{key}' advertises {info.UdpPayloadSize}."
                });
            }

            if (desired.RequireVersionZero == true && info.Version != 0) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.EdnsVersionNotAllowed,
                    Message = $"Desired state requires EDNS version 0, but '{key}' reported version {info.Version}."
                });
            }

            if (desired.RequireCookieSupport == true && !info.CookieSupported) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Warning,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.EdnsCookieNotSupported,
                    Message = $"Desired state requires DNS Cookies support, but '{key}' did not support cookies."
                });
            }
        }
    }

    private static void EvaluateDnsOverTls(string domain, DnsOverTlsAnalysis analysis, DesiredStateDnsOverTlsPolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        var servers = analysis.ServerResults ?? new Dictionary<string, DnsOverTlsEndpointResult>();
        if (desired.RequireAtLeastOneResult == true && servers.Count == 0) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Warning,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnsOverTlsNoResults,
                Message = "Desired state expected DNS over TLS results, but no results were produced."
            });
            return;
        }

        if (servers.Count == 0) {
            return;
        }

        var anySupported = servers.Values.Any(r => r != null && r.Supported);
        if (desired.RequireAnySupported == true && !anySupported) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.DnsOverTlsAnySupportedRequired,
                Message = "Desired state requires at least one authoritative server to support DNS over TLS, but none were supported."
            });
        }

        foreach (var kvp in servers) {
            var key = kvp.Key;
            var res = kvp.Value;
            if (res == null) continue;

            if (desired.RequireAllSupported == true && !res.Supported) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DnsOverTlsAllSupportedRequired,
                    Message = $"Desired state requires DNS over TLS on all probed servers, but '{key}' was not supported."
                });
                continue;
            }

            if (!res.Supported) continue;

            if (desired.RequireCertificateValid == true && res.CertificateValid == false) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DnsOverTlsCertificateInvalid,
                    Message = $"Desired state requires a valid TLS certificate for DNS over TLS, but '{key}' was invalid."
                });
            }

            if (desired.RequireHostnameMatch == true && res.HostnameMatch == false) {
                sink.Assessments.Add(new Assessment {
                    Severity = AssessmentSeverity.Error,
                    Category = "DesiredState",
                    Target = domain,
                    Code = DesiredStateCodes.DnsOverTlsCertificateMismatch,
                    Message = $"Desired state requires a DNS over TLS certificate matching the name server hostname, but '{key}' did not match."
                });
            }
        }
    }

    private static void EvaluateFlatteningService(string domain, FlatteningServiceAnalysis analysis, DesiredStateFlatteningServicePolicy? desired, DesiredStateAnalysis sink) {
        if (desired == null || desired.Enabled == false) return;
        if (analysis == null) return;

        if (desired.RequireCnameRecord == true && !analysis.CnameRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.FlatteningServiceCnameRequiredMissing,
                Message = "Desired state requires an apex CNAME record, but none was found."
            });
        }

        if (desired.DisallowCnameRecord == true && analysis.CnameRecordExists) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.FlatteningServiceCnameNotAllowed,
                Message = "Desired state disallows apex CNAME records, but a CNAME record was found."
            });
        }

        if (desired.RequireFlatteningService == true && (!analysis.CnameRecordExists || !analysis.IsFlatteningService)) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.FlatteningServiceRequiredMissing,
                Message = "Desired state requires a known flattening service, but the apex CNAME was not a recognized flattening service."
            });
        }

        if (desired.DisallowFlatteningService == true && analysis.IsFlatteningService) {
            sink.Assessments.Add(new Assessment {
                Severity = AssessmentSeverity.Error,
                Category = "DesiredState",
                Target = domain,
                Code = DesiredStateCodes.FlatteningServiceNotAllowed,
                Message = "Desired state disallows known flattening services, but a flattening service was detected."
            });
        }

        if (analysis.CnameRecordExists && desired.AllowedTargetSuffixes != null && desired.AllowedTargetSuffixes.Length > 0) {
            var suffixes = desired.AllowedTargetSuffixes
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim().Trim('.'))
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

                if (suffixes.Length > 0) {
                    var target = (analysis.Target ?? string.Empty).Trim().Trim('.');
                    if (target.Length > 0) {
                        var ok = suffixes.Any(s => DomainHelper.IsDomainOrSubdomainOf(target, s));
                        if (!ok) {
                            sink.Assessments.Add(new Assessment {
                                Severity = AssessmentSeverity.Error,
                                Category = "DesiredState",
                            Target = domain,
                            Code = DesiredStateCodes.FlatteningServiceTargetNotAllowed,
                            Message = $"Desired state requires apex CNAME target to end with [{string.Join(", ", suffixes)}], but found '{target}'."
                        });
                    }
                }
            }
        }
    }
}
