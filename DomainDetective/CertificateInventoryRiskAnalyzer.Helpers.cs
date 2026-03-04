using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective {
    public static partial class CertificateInventoryRiskAnalyzer {
        private static CertificateInventoryEndpointRisk BuildEndpointRisk(
            CertificateInventoryEntry entry,
            DateTimeOffset now,
            int expiringWithinDays,
            int criticalExpiringWithinDays) {
            var row = new CertificateInventoryEndpointRisk {
                Host = entry.ResolvedHost ?? entry.Host,
                Port = entry.Port > 0 ? entry.Port : 443,
                Service = string.IsNullOrWhiteSpace(entry.Service)
                    ? CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port)
                    : entry.Service!,
                CertificateThumbprint = entry.CertificateThumbprint?.Trim() ?? string.Empty,
                CertificateRootThumbprint = entry.CertificateRootThumbprint?.Trim() ?? string.Empty,
                CertificateSerialNumber = entry.CertificateSerialNumber?.Trim() ?? string.Empty,
                Issuer = PickIssuer(entry),
                RootIssuer = PickRoot(entry),
                AuthorityFamily = entry.CertificateAuthorityFamily ?? string.Empty,
                RootAuthorityFamily = entry.CertificateRootAuthorityFamily ?? string.Empty,
                NotBeforeUtc = entry.NotBeforeUtc,
                NotAfterUtc = entry.NotAfterUtc,
                Valid = entry.Valid,
                Expired = entry.Expired,
                ChainComplete = entry.ChainComplete,
                ChainLength = Math.Max(0, entry.CertificateChainLength),
                IntermediateCount = Math.Max(0, entry.CertificateIntermediateCount),
                HostnameMatch = entry.HostnameMatch,
                IsReachable = entry.IsReachable,
                IsSelfSigned = entry.IsSelfSigned,
                IsKnownCertificateAuthority = entry.IsKnownCertificateAuthority,
                IsKnownRootCertificateAuthority = entry.IsKnownRootCertificateAuthority,
                AllowsServerAuthentication = entry.AllowsServerAuthentication,
                AllowsClientAuthentication = entry.AllowsClientAuthentication,
                AllowsSecureEmail = entry.AllowsSecureEmail,
                AuthenticationProfile = CertificateInventoryEntryHelpers.ResolveAuthenticationProfile(entry),
                ChainSource = entry.CertificateChainSource?.Trim() ?? string.Empty,
                ChainSources = NormalizeDistinctValues(entry.CertificateChainSources),
                CtDiscoverySources = NormalizeDistinctValues(entry.CtDiscoverySources),
                CtTemplateFormatErrors = NormalizeDistinctValues(entry.CtTemplateFormatErrors),
                WeakKey = entry.WeakKey,
                Sha1Signature = entry.Sha1Signature,
                PresentInCtLogs = entry.PresentInCtLogs
            };

            var score = 0;
            if (!row.IsReachable) {
                score += 60;
                row.Reasons.Add("EndpointUnreachable");
            }

            // Derive this from timestamps so future-dated certificates are flagged consistently,
            // even when upstream snapshots incorrectly persist Valid=true.
            if (row.NotBeforeUtc.HasValue && row.NotBeforeUtc.Value > now) {
                row.NotYetValid = true;
                row.DaysUntilValid = Math.Max(0, (int)Math.Ceiling((row.NotBeforeUtc.Value - now).TotalDays));
                score += 60;
                row.Reasons.Add("CertificateNotYetValid");
            }

            if (row.NotAfterUtc.HasValue) {
                row.DaysToExpire = (int)Math.Floor((row.NotAfterUtc.Value - now).TotalDays);
            }

            if (row.Expired || (row.NotAfterUtc.HasValue && row.NotAfterUtc.Value <= now)) {
                score += 100;
                row.Reasons.Add("CertificateExpired");
            } else if (row.DaysToExpire.HasValue) {
                if (row.DaysToExpire.Value <= criticalExpiringWithinDays) {
                    score += 50;
                    row.Reasons.Add("CertificateExpiringCritical");
                } else if (row.DaysToExpire.Value <= expiringWithinDays) {
                    score += 25;
                    row.Reasons.Add("CertificateExpiringSoon");
                }
            }

            // Keep the generic validation failure reason alongside specific root causes
            // (for example NotYetValid) so broad dashboards can still aggregate by validation.
            if (!row.Valid && row.IsReachable) {
                score += 45;
                row.Reasons.Add("CertificateValidationFailed");
            }

            if (!row.ChainComplete && row.IsReachable && !row.IsSelfSigned) {
                score += 35;
                row.Reasons.Add("ChainIncomplete");
            }

            if (!row.HostnameMatch && row.IsReachable) {
                score += 35;
                row.Reasons.Add("HostnameMismatch");
            }

            if (!row.AllowsServerAuthentication && row.IsReachable) {
                score += 40;
                row.Reasons.Add("MissingServerAuthEku");
            }

            if (row.IsSelfSigned) {
                score += 30;
                row.Reasons.Add("SelfSignedCertificate");
            }

            if (row.WeakKey) {
                score += 35;
                row.Reasons.Add("WeakKey");
            }

            if (row.Sha1Signature) {
                score += 40;
                row.Reasons.Add("Sha1Signature");
            }

            if (!row.IsKnownCertificateAuthority && !row.IsSelfSigned && row.IsReachable) {
                score += 10;
                row.Reasons.Add("UnknownAuthority");
            }

            if (!row.PresentInCtLogs && row.IsKnownCertificateAuthority && row.IsReachable) {
                score += 10;
                row.Reasons.Add("CtNotObserved");
            }

            row.Score = Math.Max(0, Math.Min(100, score));
            row.Severity = PickSeverity(row.Score);
            return row;
        }

        private static void Increment(Dictionary<string, int> counters, string key) {
            if (string.IsNullOrWhiteSpace(key)) {
                return;
            }

            counters[key] = counters.TryGetValue(key, out var count) ? count + 1 : 1;
        }

        private static void IncrementSeverity(CertificateInventoryRiskSummary summary, string severity) {
            if (string.Equals(severity, "Critical", StringComparison.OrdinalIgnoreCase)) {
                summary.CriticalCount++;
            } else if (string.Equals(severity, "High", StringComparison.OrdinalIgnoreCase)) {
                summary.HighCount++;
            } else if (string.Equals(severity, "Medium", StringComparison.OrdinalIgnoreCase)) {
                summary.MediumCount++;
            } else if (string.Equals(severity, "Low", StringComparison.OrdinalIgnoreCase)) {
                summary.LowCount++;
            } else {
                summary.NoRiskCount++;
            }
        }

        private static string PickSeverity(int score) {
            if (score >= 85) {
                return "Critical";
            }
            if (score >= 60) {
                return "High";
            }
            if (score >= 30) {
                return "Medium";
            }
            if (score > 0) {
                return "Low";
            }

            return "None";
        }

        private static string BuildEndpointKey(CertificateInventoryEntry entry) {
            return CertificateInventoryEndpointKey.Build(entry);
        }

        private static Dictionary<string, CertificateReuseStats> BuildCertificateReuseStats(IEnumerable<LatestEntryState> latestStates) {
            var grouped = new Dictionary<string, List<CertificateInventoryEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (var latest in latestStates ?? Enumerable.Empty<LatestEntryState>()) {
                if (latest?.Entry == null) {
                    continue;
                }

                var certificateId = BuildCertificateId(latest.Entry);
                if (!grouped.TryGetValue(certificateId, out var entries)) {
                    entries = new List<CertificateInventoryEntry>();
                    grouped[certificateId] = entries;
                }
                entries.Add(latest.Entry);
            }

            var results = new Dictionary<string, CertificateReuseStats>(StringComparer.OrdinalIgnoreCase);
            foreach (var pair in grouped) {
                var entries = pair.Value;
                if (entries.Count == 0) {
                    continue;
                }

                var distinctServices = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var distinctPorts = new HashSet<int>();
                foreach (var entry in entries) {
                    distinctServices.Add(PickService(entry));
                    distinctPorts.Add(entry.Port > 0 ? entry.Port : 443);
                }

                results[pair.Key] = new CertificateReuseStats {
                    EndpointCount = entries.Count,
                    DistinctServiceCount = distinctServices.Count,
                    DistinctPortCount = distinctPorts.Count
                };
            }

            return results;
        }

        private static string BuildCertificateId(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
                return NormalizeHexIdentifier(entry.CertificateThumbprint);
            }

            var subject = entry.CertificateSubject ?? string.Empty;
            var issuer = PickIssuer(entry);
            var notBefore = entry.NotBeforeUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            var notAfter = entry.NotAfterUtc?.ToString("O", CultureInfo.InvariantCulture) ?? string.Empty;
            return $"{subject}|{issuer}|{notBefore}|{notAfter}";
        }

        private static string PickService(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.Service)) {
                return entry.Service!;
            }

            return CertificateServiceClassifier.GuessService(entry.Scheme ?? "https", entry.Port);
        }

        private static List<string> NormalizeDistinctValues(IEnumerable<string>? values) {
            if (values == null) {
                return new List<string>();
            }

            return values
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private static string NormalizeHexIdentifier(string? value) {
            if (string.IsNullOrWhiteSpace(value)) {
                return string.Empty;
            }

            var chars = value.Where(c => !char.IsWhiteSpace(c) && c != ':').ToArray();
            return new string(chars).Trim().ToUpperInvariant();
        }

        private static string PickIssuer(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuerNormalized)) {
                return entry.CertificateIssuerNormalized!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuerOrganization)) {
                return entry.CertificateIssuerOrganization!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateIssuer)) {
                return CertificateIssuerClassifier.Classify(entry.CertificateIssuer).NormalizedName;
            }
            return "Unknown";
        }

        private static string PickRoot(CertificateInventoryEntry entry) {
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuerNormalized)) {
                return entry.CertificateRootIssuerNormalized!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuerOrganization)) {
                return entry.CertificateRootIssuerOrganization!;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootIssuer)) {
                return CertificateIssuerClassifier.Classify(entry.CertificateRootIssuer).NormalizedName;
            }
            if (!string.IsNullOrWhiteSpace(entry.CertificateRootSubject)) {
                return entry.CertificateRootSubject!;
            }
            return "Unknown";
        }
    }
}
