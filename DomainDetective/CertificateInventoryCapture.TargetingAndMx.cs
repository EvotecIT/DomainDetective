using DnsClientX;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

public sealed partial class CertificateInventoryCapture {
    private sealed class RecentInventoryEndpointEntry {
        public required CertificateInventoryEntry Entry { get; init; }

        public required DateTimeOffset CapturedAtUtc { get; init; }
    }

    private enum ReusedTargetKind {
        Https,
        Mail
    }

    private sealed class ReusedRecentSuccessCandidate {
        public required ReusedTargetKind Kind { get; init; }

        public required string Target { get; init; }

        public required string Service { get; init; }

        public required CertificateInventoryEntry Entry { get; init; }

        public required int Priority { get; init; }

        public required int SortDays { get; init; }

        public IReadOnlyCollection<string> TargetOrigins { get; init; } = Array.Empty<string>();

        public MailEndpointTarget? MailTarget { get; init; }
    }

    private static string BuildMailTargetLabel(MailEndpointTarget target) {
        return $"{target.Scheme}://{EndpointHostNormalizer.FormatForUriAuthority(target.Host)}:{target.Port}";
    }

    private static string BuildEndpointKey(string host, int port, string service) {
        return CertificateInventoryEndpointKey.Build(host, null, port, service, null);
    }

    private static bool ProbeVantageMatches(CertificateInventoryEntry entry, string? requestedVantage) {
        return CertificateInventoryProbeVantage.Equals(entry.ProbeVantage, requestedVantage);
    }

    private static bool TryBuildHttpsEndpointKey(string target, out string key) {
        key = string.Empty;
        if (string.IsNullOrWhiteSpace(target)) {
            return false;
        }

        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host)) {
            return false;
        }

        var port = uri.IsDefaultPort ? 443 : uri.Port;
        var service = CertificateServiceClassifier.GuessService(Uri.UriSchemeHttps, port);
        key = BuildEndpointKey(uri.Host, port, service);
        return true;
    }

    private static bool ShouldReuseCachedSuccessEntry(CertificateInventoryEntry entry, DateTimeOffset now, int reprobeExpiringWithinDays) {
        if (entry == null) {
            return false;
        }
        if (!entry.IsReachable) {
            return false;
        }
        if (string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
            return false;
        }
        if (entry.Expired) {
            return false;
        }
        if (entry.NotAfterUtc.HasValue) {
            var cutoff = now.AddDays(Math.Max(0, reprobeExpiringWithinDays));
            var notAfter = entry.NotAfterUtc.Value;
            if (notAfter <= cutoff) {
                return false;
            }
        }
        return true;
    }

    private static bool ShouldReuseCachedFailureEntry(CertificateInventoryEntry entry) {
        if (entry == null) {
            return false;
        }
        if (!string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
            return false;
        }

        var failureKind = entry.FailureKind != CertificateFailureKind.None
            ? entry.FailureKind
            : CertificateFailureClassifier.ClassifyFailureReason(entry.FailureReason);
        return CertificateFailureClassifier.IsStableForSnapshotReuse(failureKind);
    }

    private static bool ShouldLoadRecentSnapshotEntries(CertificateInventoryCaptureOptions options) {
        if (options == null) {
            return false;
        }

        return ResolveEffectiveRecentSnapshotReuseTtl(options) > TimeSpan.Zero;
    }

    private static TimeSpan ResolveEffectiveRecentSnapshotReuseTtl(CertificateInventoryCaptureOptions options) {
        if (options == null) {
            return TimeSpan.Zero;
        }

        TimeSpan successfulReuseTtl =
            options.ReuseRecentSnapshotEntries && options.RecentSnapshotTtl > TimeSpan.Zero
                ? options.RecentSnapshotTtl
                : TimeSpan.Zero;
        TimeSpan stableFailureReuseTtl =
            options.ReuseRecentFailureSnapshotEntries && options.RecentFailureSnapshotTtl > TimeSpan.Zero
                ? options.RecentFailureSnapshotTtl
                : TimeSpan.Zero;
        return successfulReuseTtl >= stableFailureReuseTtl ? successfulReuseTtl : stableFailureReuseTtl;
    }

    private static bool TryReuseCachedEntry(
        RecentInventoryEndpointEntry cachedEntry,
        DateTimeOffset now,
        CertificateInventoryCaptureOptions options,
        out bool reusedStableFailure) {
        reusedStableFailure = false;
        if (cachedEntry == null || cachedEntry.Entry == null || options == null) {
            return false;
        }

        DateTimeOffset observedAtUtc = cachedEntry.Entry.ObservedAtUtc ?? cachedEntry.CapturedAtUtc;

        if (options.ReuseRecentSnapshotEntries &&
            options.RecentSnapshotTtl > TimeSpan.Zero &&
            observedAtUtc >= now - options.RecentSnapshotTtl &&
            ShouldReuseCachedSuccessEntry(cachedEntry.Entry, now, options.ReprobeExpiringWithinDays)) {
            return true;
        }

        if (options.ReuseRecentFailureSnapshotEntries &&
            options.RecentFailureSnapshotTtl > TimeSpan.Zero &&
            observedAtUtc >= now - options.RecentFailureSnapshotTtl &&
            ShouldReuseCachedFailureEntry(cachedEntry.Entry)) {
            reusedStableFailure = true;
            return true;
        }

        return false;
    }

    private static IReadOnlyDictionary<string, RecentInventoryEndpointEntry> WrapRecentSnapshotEntries(
        IReadOnlyDictionary<string, CertificateInventoryEntry> entries,
        DateTimeOffset capturedAtUtc) {
        if (entries == null || entries.Count == 0) {
            return new Dictionary<string, RecentInventoryEndpointEntry>(StringComparer.OrdinalIgnoreCase);
        }

        return entries
            .Where(static pair => pair.Value != null)
            .ToDictionary(
                static pair => pair.Key,
                pair => {
                    CertificateInventoryEntryHelpers.NormalizeRemoteAddressEvidence(pair.Value);
                    return new RecentInventoryEndpointEntry {
                        Entry = pair.Value,
                        CapturedAtUtc = capturedAtUtc
                    };
                },
                StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyDictionary<string, RecentInventoryEndpointEntry> LoadRecentSnapshotEntries(CertificateInventoryCaptureOptions options, DateTimeOffset now) {
        TimeSpan effectiveTtl = ResolveEffectiveRecentSnapshotReuseTtl(options);
        if (options == null || effectiveTtl <= TimeSpan.Zero) {
            return new Dictionary<string, RecentInventoryEndpointEntry>(StringComparer.OrdinalIgnoreCase);
        }

        using var monitor = new CertificateMonitor {
            CacheDirectory = options.CacheDirectory,
            PersistInventorySnapshots = false
        };

        var since = now - effectiveTtl;
        var snapshots = monitor.LoadInventorySnapshots(sinceUtc: since, latestOnly: false);
        if (snapshots.Count == 0) {
            return new Dictionary<string, RecentInventoryEndpointEntry>(StringComparer.OrdinalIgnoreCase);
        }

        var ordered = snapshots.OrderBy(snapshot => snapshot.CapturedAtUtc).ToList();
        var byEndpoint = new Dictionary<string, RecentInventoryEndpointEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var snapshot in ordered) {
            if (snapshot.Entries == null || snapshot.Entries.Count == 0) {
                continue;
            }
            foreach (var entry in snapshot.Entries) {
                if (entry == null) {
                    continue;
                }
                if (!ProbeVantageMatches(entry, options.ProbeVantage)) {
                    continue;
                }
                var host = !string.IsNullOrWhiteSpace(entry.ResolvedHost) ? entry.ResolvedHost! : entry.Host;
                if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(entry.Service) || entry.Port <= 0) {
                    continue;
                }
                if (!entry.ObservedAtUtc.HasValue) {
                    entry.ObservedAtUtc = snapshot.CapturedAtUtc;
                }
                CertificateInventoryEntryHelpers.NormalizeRemoteAddressEvidence(entry);
                var key = BuildEndpointKey(host, entry.Port, entry.Service);
                byEndpoint[key] = new RecentInventoryEndpointEntry {
                    Entry = entry,
                    CapturedAtUtc = snapshot.CapturedAtUtc
                };
            }
        }

        return byEndpoint;
    }

    private static void ApplyTargetLimit(
        CertificateInventoryCaptureOptions options,
        int maxTargets,
        HashSet<string> httpsTargets,
        Dictionary<string, HashSet<string>> httpsTargetOriginsByEndpointKey,
        Dictionary<string, MailEndpointTarget> mailTargets,
        List<string> warnings,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint,
        int reprobeExpiringWithinDays,
        List<TargetDecisionDiagnosticEntry> targetDecisionDiagnostics) {
        if (maxTargets < 0) {
            return;
        }

        var totalTargets = httpsTargets.Count + mailTargets.Count;
        if (totalTargets <= maxTargets) {
            return;
        }

        var originalHttps = httpsTargets.Count;
        var originalMail = mailTargets.Count;
        var limit = maxTargets;
        ResolveTargetBudget(
            originalHttps,
            originalMail,
            limit,
            out var allowedHttps,
            out var allowedMail);

        if (originalMail > allowedMail) {
            var rankedMail = mailTargets.Values
                .Select(target => new {
                    Target = target,
                    Priority = ComputeMailTargetPriority(target, recentByEndpoint, reprobeExpiringWithinDays)
                })
                .OrderByDescending(item => item.Priority)
                .ThenBy(item => ResolvePrioritySortDays(item.Target, recentByEndpoint))
                .ThenBy(item => item.Target.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.Target.Port)
                .ThenBy(item => item.Target.Service, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var keptMail = rankedMail
                .Select(static item => item.Target)
                .Take(allowedMail)
                .ToList();
            var droppedMail = rankedMail
                .Skip(allowedMail)
                .ToList();

            foreach (var item in droppedMail) {
                targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                    Stage = "target-limit",
                    Action = "pruned",
                    Reason = "max-targets",
                    Target = BuildMailTargetLabel(item.Target),
                    Service = item.Target.Service,
                    PriorityScore = item.Priority,
                    Message = $"Pruned by MaxTargets={options.MaxTargets}.",
                    TargetOrigins = item.Target.TargetOrigins
                });
            }

            mailTargets.Clear();
            foreach (var target in keptMail) {
                AddMailTarget(mailTargets, target);
            }
        }

        if (originalHttps > allowedHttps) {
            var rankedHttps = httpsTargets
                .Select(target => new {
                    Target = target,
                    Priority = ComputeHttpsTargetPriority(target, recentByEndpoint, reprobeExpiringWithinDays)
                })
                .OrderByDescending(item => item.Priority)
                .ThenBy(item => ResolvePrioritySortDays(item.Target, recentByEndpoint))
                .ThenBy(item => item.Target, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var keptHttps = rankedHttps
                .Select(static item => item.Target)
                .Take(allowedHttps)
                .ToList();
            var droppedHttps = rankedHttps
                .Skip(allowedHttps)
                .ToList();

            foreach (var item in droppedHttps) {
                string endpointKey = TryBuildHttpsEndpointKey(item.Target, out string key)
                    ? key
                    : item.Target;
                targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                    Stage = "target-limit",
                    Action = "pruned",
                    Reason = "max-targets",
                    Target = item.Target,
                    Service = "HTTPS",
                    PriorityScore = item.Priority,
                    Message = $"Pruned by MaxTargets={options.MaxTargets}.",
                    TargetOrigins = GetTrackedOrigins(httpsTargetOriginsByEndpointKey, endpointKey)
                });
            }

            httpsTargets.Clear();
            foreach (var target in keptHttps) {
                httpsTargets.Add(target);
            }

            PruneTrackedHttpsOrigins(httpsTargetOriginsByEndpointKey, keptHttps);
        }

        warnings.Add($"Probe target list capped from {totalTargets} to {httpsTargets.Count + mailTargets.Count} within global MaxTargets={options.MaxTargets} (HTTPS: {originalHttps}->{httpsTargets.Count}, Mail: {originalMail}->{mailTargets.Count}).");
    }

    private static void ApplyTargetLimitIncludingReusedSuccesses(
        CertificateInventoryCaptureOptions options,
        int maxTargets,
        HashSet<string> httpsTargets,
        Dictionary<string, HashSet<string>> httpsTargetOriginsByEndpointKey,
        Dictionary<string, MailEndpointTarget> mailTargets,
        List<CertificateInventoryEntry> cachedEntries,
        List<ReusedRecentSuccessCandidate> reusedSuccessCandidates,
        List<string> warnings,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint,
        int reprobeExpiringWithinDays,
        List<TargetDecisionDiagnosticEntry> targetDecisionDiagnostics,
        ref int reusedHttps,
        ref int reusedMail) {
        if (reusedSuccessCandidates.Count == 0) {
            ApplyTargetLimit(
                options,
                maxTargets,
                httpsTargets,
                httpsTargetOriginsByEndpointKey,
                mailTargets,
                warnings,
                recentByEndpoint,
                reprobeExpiringWithinDays,
                targetDecisionDiagnostics);
            return;
        }

        if (maxTargets < 0) {
            cachedEntries.AddRange(reusedSuccessCandidates.Select(static candidate => candidate.Entry));
            reusedHttps += reusedSuccessCandidates.Count(static candidate => candidate.Kind == ReusedTargetKind.Https);
            reusedMail += reusedSuccessCandidates.Count(static candidate => candidate.Kind == ReusedTargetKind.Mail);
            return;
        }

        var originalHttps = httpsTargets.Count + reusedSuccessCandidates.Count(static candidate => candidate.Kind == ReusedTargetKind.Https);
        var originalMail = mailTargets.Count + reusedSuccessCandidates.Count(static candidate => candidate.Kind == ReusedTargetKind.Mail);
        var totalTargets = originalHttps + originalMail;
        if (totalTargets <= maxTargets) {
            cachedEntries.AddRange(reusedSuccessCandidates.Select(static candidate => candidate.Entry));
            reusedHttps += reusedSuccessCandidates.Count(static candidate => candidate.Kind == ReusedTargetKind.Https);
            reusedMail += reusedSuccessCandidates.Count(static candidate => candidate.Kind == ReusedTargetKind.Mail);
            return;
        }

        ResolveTargetBudget(
            originalHttps,
            originalMail,
            maxTargets,
            out var allowedHttps,
            out var allowedMail);

        var keptHttps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var keptMail = new List<MailEndpointTarget>();
        var keptReused = new List<ReusedRecentSuccessCandidate>();

        if (originalHttps > 0) {
            var rankedHttps = new List<(string Target, int Priority, int SortDays, ReusedRecentSuccessCandidate? Reused)>(originalHttps);
            foreach (var target in httpsTargets) {
                rankedHttps.Add((
                    Target: target,
                    Priority: ComputeHttpsTargetPriority(target, recentByEndpoint, reprobeExpiringWithinDays),
                    SortDays: ResolvePrioritySortDays(target, recentByEndpoint),
                    Reused: null));
            }

            foreach (var candidate in reusedSuccessCandidates.Where(static item => item.Kind == ReusedTargetKind.Https)) {
                rankedHttps.Add((
                    Target: candidate.Target,
                    Priority: candidate.Priority,
                    SortDays: candidate.SortDays,
                    Reused: candidate));
            }

            var orderedHttps = rankedHttps
                .OrderByDescending(static item => item.Priority)
                .ThenBy(static item => item.SortDays)
                .ThenBy(static item => item.Target, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var item in orderedHttps.Take(allowedHttps)) {
                if (item.Reused != null) {
                    keptReused.Add(item.Reused);
                } else {
                    keptHttps.Add(item.Target);
                }
            }

            foreach (var item in orderedHttps.Skip(allowedHttps)) {
                if (item.Reused != null) {
                    targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                        Stage = "target-limit",
                        Action = "pruned",
                        Reason = "max-targets",
                        Target = item.Target,
                        Service = item.Reused.Service,
                        PriorityScore = item.Priority,
                        Message = $"Pruned by MaxTargets={options.MaxTargets}.",
                        TargetOrigins = item.Reused.TargetOrigins.ToList()
                    });
                    continue;
                }

                string endpointKey = TryBuildHttpsEndpointKey(item.Target, out string key)
                    ? key
                    : item.Target;
                targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                    Stage = "target-limit",
                    Action = "pruned",
                    Reason = "max-targets",
                    Target = item.Target,
                    Service = "HTTPS",
                    PriorityScore = item.Priority,
                    Message = $"Pruned by MaxTargets={options.MaxTargets}.",
                    TargetOrigins = GetTrackedOrigins(httpsTargetOriginsByEndpointKey, endpointKey).ToList()
                });
            }
        }

        if (originalMail > 0) {
            var rankedMail = new List<(MailEndpointTarget Target, int Priority, int SortDays, ReusedRecentSuccessCandidate? Reused)>(originalMail);
            foreach (var target in mailTargets.Values) {
                rankedMail.Add((
                    Target: target,
                    Priority: ComputeMailTargetPriority(target, recentByEndpoint, reprobeExpiringWithinDays),
                    SortDays: ResolvePrioritySortDays(target, recentByEndpoint),
                    Reused: null));
            }

            foreach (var candidate in reusedSuccessCandidates.Where(static item => item.Kind == ReusedTargetKind.Mail && item.MailTarget != null)) {
                rankedMail.Add((
                    Target: candidate.MailTarget!,
                    Priority: candidate.Priority,
                    SortDays: candidate.SortDays,
                    Reused: candidate));
            }

            var orderedMail = rankedMail
                .OrderByDescending(static item => item.Priority)
                .ThenBy(static item => item.SortDays)
                .ThenBy(static item => item.Target.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(static item => item.Target.Port)
                .ThenBy(static item => item.Target.Service, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var item in orderedMail.Take(allowedMail)) {
                if (item.Reused != null) {
                    keptReused.Add(item.Reused);
                } else {
                    keptMail.Add(item.Target);
                }
            }

            foreach (var item in orderedMail.Skip(allowedMail)) {
                targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                    Stage = "target-limit",
                    Action = "pruned",
                    Reason = "max-targets",
                    Target = BuildMailTargetLabel(item.Target),
                    Service = item.Target.Service,
                    PriorityScore = item.Priority,
                    Message = $"Pruned by MaxTargets={options.MaxTargets}.",
                    TargetOrigins = (item.Reused?.TargetOrigins ?? item.Target.TargetOrigins).ToList()
                });
            }
        }

        httpsTargets.Clear();
        foreach (var target in keptHttps) {
            httpsTargets.Add(target);
        }
        PruneTrackedHttpsOrigins(httpsTargetOriginsByEndpointKey, keptHttps);

        mailTargets.Clear();
        foreach (var target in keptMail) {
            AddMailTarget(mailTargets, target);
        }

        cachedEntries.AddRange(keptReused.Select(static candidate => candidate.Entry));
        reusedHttps += keptReused.Count(static candidate => candidate.Kind == ReusedTargetKind.Https);
        reusedMail += keptReused.Count(static candidate => candidate.Kind == ReusedTargetKind.Mail);

        int keptHttpsCount = httpsTargets.Count + keptReused.Count(static candidate => candidate.Kind == ReusedTargetKind.Https);
        int keptMailCount = mailTargets.Count + keptReused.Count(static candidate => candidate.Kind == ReusedTargetKind.Mail);
        warnings.Add($"Probe target list capped from {totalTargets} to {keptHttpsCount + keptMailCount} within global MaxTargets={options.MaxTargets} (HTTPS: {originalHttps}->{keptHttpsCount}, Mail: {originalMail}->{keptMailCount}).");
    }

    private static int ComputeHttpsTargetPriority(
        string target,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint,
        int reprobeExpiringWithinDays) {
        if (recentByEndpoint != null &&
            TryBuildHttpsEndpointKey(target, out var endpointKey) &&
            recentByEndpoint.TryGetValue(endpointKey, out var cachedEntry)) {
            return ComputeCachedEntryPriority(cachedEntry.Entry, reprobeExpiringWithinDays);
        }

        return 1000;
    }

    private static int ComputeMailTargetPriority(
        MailEndpointTarget target,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint,
        int reprobeExpiringWithinDays) {
        if (target == null) {
            return 0;
        }

        if (TryGetCachedMailEntry(target, recentByEndpoint, out var cachedEntry)) {
            return ComputeCachedEntryPriority(cachedEntry!.Entry, reprobeExpiringWithinDays);
        }

        return 1000;
    }

    private static int ResolvePrioritySortDays(
        string target,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint) {
        if (recentByEndpoint != null &&
            TryBuildHttpsEndpointKey(target, out var endpointKey) &&
            recentByEndpoint.TryGetValue(endpointKey, out var cachedEntry)) {
            return ParseSortDays(cachedEntry.Entry);
        }

        return int.MinValue;
    }

    private static int ResolvePrioritySortDays(
        MailEndpointTarget target,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint) {
        if (TryGetCachedMailEntry(target, recentByEndpoint, out var cachedEntry)) {
            return ParseSortDays(cachedEntry!.Entry);
        }

        return int.MinValue;
    }

    private static bool TryGetCachedMailEntry(
        MailEndpointTarget target,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint,
        out RecentInventoryEndpointEntry? cachedEntry) {
        cachedEntry = null;
        if (target == null || recentByEndpoint == null) {
            return false;
        }

        var endpointKey = BuildEndpointKey(target.Host, target.Port, target.Service);
        return recentByEndpoint.TryGetValue(endpointKey, out cachedEntry);
    }

    private static int ComputeCachedEntryPriority(CertificateInventoryEntry entry, int reprobeExpiringWithinDays) {
        if (entry == null) {
            return 0;
        }

        var score = 0;
        if (!entry.IsReachable) {
            score += 2000;
        }
        if (string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
            score += 1900;
        }
        if (entry.NotBeforeUtc.HasValue && entry.NotBeforeUtc.Value > DateTimeOffset.UtcNow) {
            score += 1800;
        }
        if (entry.Expired) {
            score += 1700;
        }
        if (!entry.Valid && entry.IsReachable) {
            score += 1600;
        }

        if (entry.NotAfterUtc.HasValue) {
            var daysToExpiry = (int)Math.Floor((entry.NotAfterUtc.Value - DateTimeOffset.UtcNow).TotalDays);
            if (daysToExpiry <= Math.Max(0, reprobeExpiringWithinDays)) {
                score += 1500;
            } else if (daysToExpiry <= 30) {
                score += 1400;
            } else if (daysToExpiry <= 90) {
                score += 1200;
            }
        }

        if (entry.WeakKey) {
            score += 1100;
        }
        if (entry.Sha1Signature) {
            score += 1100;
        }
        if (!entry.AllowsServerAuthentication) {
            score += 1050;
        }
        if (!entry.IsSelfSigned && !entry.IsKnownCertificateAuthority) {
            score += 1025;
        }
        if (entry.IsKnownCertificateAuthority && !entry.PresentInCtLogs) {
            score += 1010;
        }
        if (entry.AllowsClientAuthentication) {
            score += 1005;
        }
        if (entry.AllowsSecureEmail) {
            score += 1001;
        }

        return score;
    }

    private static int ParseSortDays(CertificateInventoryEntry entry) {
        if (entry == null || !entry.NotAfterUtc.HasValue) {
            return int.MaxValue;
        }

        return (int)Math.Floor((entry.NotAfterUtc.Value - DateTimeOffset.UtcNow).TotalDays);
    }

    private static int ResolveFtpTlsTargetBudget(
        int ftpTlsCount,
        int nonFtpCount,
        int maxTargets) {
        int normalizedFtpTls = Math.Max(0, ftpTlsCount);
        int normalizedNonFtp = Math.Max(0, nonFtpCount);
        if (maxTargets <= 0 || normalizedFtpTls == 0) {
            return 0;
        }
        if (normalizedNonFtp == 0) {
            return Math.Min(normalizedFtpTls, maxTargets);
        }
        if (maxTargets == 1) {
            // FTP TLS targets are always explicit caller inputs. Honor that request
            // ahead of automatically expanded HTTPS or mail targets when only one
            // global slot exists.
            return 1;
        }

        int total = normalizedFtpTls + normalizedNonFtp;
        int desired = (int)Math.Round(
            maxTargets * (double)normalizedFtpTls / total,
            MidpointRounding.AwayFromZero);
        desired = Math.Max(1, Math.Min(maxTargets - 1, desired));
        return Math.Min(normalizedFtpTls, desired);
    }

    private static void ApplyFtpTlsTargetLimit(
        CertificateInventoryCaptureOptions options,
        Dictionary<string, FtpTlsEndpointTarget> ftpTlsTargets,
        int allowedTargets,
        List<string> warnings,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint,
        List<TargetDecisionDiagnosticEntry> targetDecisionDiagnostics) {
        if (ftpTlsTargets.Count <= allowedTargets) {
            return;
        }

        int originalCount = ftpTlsTargets.Count;
        var ordered = ftpTlsTargets.Values
            .Select(target => new {
                Target = target,
                Priority = ComputeFtpTlsTargetPriority(target, recentByEndpoint, options),
                SortDays = ResolvePrioritySortDays(target, recentByEndpoint)
            })
            .OrderByDescending(item => item.Priority)
            .ThenBy(item => item.SortDays)
            .ThenBy(item => item.Target.Host, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Target.Port)
            .ThenBy(item => item.Target.Service, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var kept = ordered.Take(Math.Max(0, allowedTargets)).ToArray();
        var pruned = ordered.Skip(Math.Max(0, allowedTargets)).ToArray();

        ftpTlsTargets.Clear();
        foreach (var item in kept) {
            ftpTlsTargets[item.Target.Key] = item.Target;
        }
        foreach (var item in pruned) {
            FtpTlsEndpointTarget target = item.Target;
            targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                Stage = "target-limit",
                Action = "pruned",
                Reason = "max-targets",
                Target = $"{target.Scheme}://{EndpointHostNormalizer.FormatForUriAuthority(target.Host)}:{target.Port}",
                Service = target.Service,
                PriorityScore = item.Priority,
                Message = $"Pruned by MaxTargets={options.MaxTargets}.",
                TargetOrigins = target.TargetOrigins.ToList()
            });
        }

        warnings.Add($"FTP TLS target list capped from {originalCount} to {ftpTlsTargets.Count} by the global MaxTargets budget.");
    }

    private static int ComputeFtpTlsTargetPriority(
        FtpTlsEndpointTarget target,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint,
        CertificateInventoryCaptureOptions options) {
        if (target != null &&
            recentByEndpoint != null &&
            recentByEndpoint.TryGetValue(target.Key, out RecentInventoryEndpointEntry? cachedEntry)) {
            int evidencePriority = ComputeCachedEntryPriority(cachedEntry.Entry, options.ReprobeExpiringWithinDays);
            if (TryReuseCachedEntry(cachedEntry, DateTimeOffset.UtcNow, options, out _)) {
                // Reusable successes do not need a live probe. Keep them below every
                // uncached target even when their cached evidence carries a high score.
                return Math.Min(999, evidencePriority);
            }
            // Stale or otherwise non-reusable observations require fresh evidence and
            // therefore outrank both uncached targets and reusable successes.
            return Math.Max(1001, evidencePriority);
        }
        return 1000;
    }

    private static int ResolvePrioritySortDays(
        FtpTlsEndpointTarget target,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint) {
        if (target != null &&
            recentByEndpoint != null &&
            recentByEndpoint.TryGetValue(target.Key, out RecentInventoryEndpointEntry? cachedEntry)) {
            return ParseSortDays(cachedEntry.Entry);
        }
        return int.MinValue;
    }

    private static void ResolveTargetBudget(
        int httpsCount,
        int mailCount,
        int maxTargets,
        out int allowedHttps,
        out int allowedMail) {
        allowedHttps = 0;
        allowedMail = 0;
        if (maxTargets <= 0) {
            return;
        }

        var normalizedHttps = Math.Max(0, httpsCount);
        var normalizedMail = Math.Max(0, mailCount);
        if (normalizedHttps == 0) {
            allowedMail = Math.Min(normalizedMail, maxTargets);
            return;
        }
        if (normalizedMail == 0) {
            allowedHttps = Math.Min(normalizedHttps, maxTargets);
            return;
        }

        // When a run is only allowed to probe one endpoint, prefer the direct HTTPS
        // target over auxiliary mail expansion. This keeps apex/root website checks
        // from being starved by MX-derived targets during tightly bounded passes.
        if (maxTargets == 1) {
            allowedHttps = 1;
            allowedMail = 0;
            return;
        }

        var total = normalizedHttps + normalizedMail;
        var desiredHttps = (int)Math.Round(
            maxTargets * (double)normalizedHttps / total,
            MidpointRounding.AwayFromZero);
        if (desiredHttps < 1) {
            desiredHttps = 1;
        }
        if (desiredHttps > maxTargets - 1) {
            desiredHttps = maxTargets - 1;
        }

        allowedHttps = Math.Min(normalizedHttps, desiredHttps);
        allowedMail = Math.Min(normalizedMail, maxTargets - allowedHttps);

        var remaining = maxTargets - (allowedHttps + allowedMail);
        if (remaining <= 0) {
            return;
        }

        var httpsRoom = normalizedHttps - allowedHttps;
        if (httpsRoom > 0) {
            var addHttps = Math.Min(remaining, httpsRoom);
            allowedHttps += addHttps;
            remaining -= addHttps;
        }

        if (remaining <= 0) {
            return;
        }

        var mailRoom = normalizedMail - allowedMail;
        if (mailRoom > 0) {
            var addMail = Math.Min(remaining, mailRoom);
            allowedMail += addMail;
        }
    }

    private static void ApplyAdditionalEndpoints(
        CertificateInventoryCaptureOptions options,
        HashSet<string> httpsTargets,
        Dictionary<string, HashSet<string>> httpsTargetOriginsByEndpointKey,
        Dictionary<string, MailEndpointTarget> mailTargets,
        Dictionary<string, FtpTlsEndpointTarget> ftpTlsTargets,
        List<string> warnings,
        List<TargetDecisionDiagnosticEntry> targetDecisionDiagnostics) {
        foreach (var raw in options.AdditionalEndpoints) {
            if (string.IsNullOrWhiteSpace(raw)) {
                continue;
            }
            var value = raw.Trim();
            if (value.IndexOf("://", StringComparison.Ordinal) >= 0) {
                if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                    string.IsNullOrWhiteSpace(uri.Host) ||
                    !EndpointHostNormalizer.TryNormalize(uri.Host, out _)) {
                    warnings.Add($"Skipping invalid endpoint '{value}'.");
                    targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                        Stage = "additional-endpoints",
                        Action = "rejected",
                        Reason = "invalid-endpoint",
                        Target = value,
                        Message = "The additional endpoint could not be parsed into a supported absolute URI."
                    });
                    continue;
                }

                if (TryGetExplicitUriPort(uri, out int explicitPort) &&
                    (explicitPort < 1 || explicitPort > 65535)) {
                    warnings.Add($"Skipping invalid endpoint '{value}'.");
                    targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                        Stage = "additional-endpoints",
                        Action = "rejected",
                        Reason = "invalid-endpoint",
                        Target = value,
                        Service = uri.Scheme.ToLowerInvariant(),
                        Message = "An explicitly supplied endpoint port must be between 1 and 65535."
                    });
                    continue;
                }

                var scheme = uri.Scheme.ToLowerInvariant();
                if (scheme == Uri.UriSchemeHttp || scheme == Uri.UriSchemeHttps) {
                    var builder = new UriBuilder(uri) {
                        Scheme = Uri.UriSchemeHttps,
                        Port = uri.IsDefaultPort ? options.HttpsPort : uri.Port
                    };
                    AddHttpsTarget(
                        httpsTargets,
                        httpsTargetOriginsByEndpointKey,
                        builder.Uri.ToString(),
                        TargetOriginAdditionalEndpoint);
                    continue;
                }

                if (TryCreateMailTargetFromScheme(uri, options, out var target)) {
                    target!.TargetOrigins.Add(TargetOriginAdditionalEndpoint);
                    AddMailTarget(mailTargets, target!);
                    continue;
                }

                if (IsFtpTlsScheme(scheme)) {
                    if (TryCreateFtpTlsTargetFromScheme(uri, out FtpTlsEndpointTarget? ftpTlsTarget)) {
                        ftpTlsTarget!.TargetOrigins.Add(TargetOriginAdditionalEndpoint);
                        ftpTlsTargets[ftpTlsTarget.Key] = ftpTlsTarget;
                    } else {
                        warnings.Add($"Skipping invalid FTP TLS endpoint '{value}'.");
                        targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                            Stage = "additional-endpoints",
                            Action = "rejected",
                            Reason = "invalid-endpoint",
                            Target = value,
                            Service = scheme,
                            Message = "The FTP TLS endpoint requires a valid hostname and a port between 1 and 65535."
                        });
                    }
                    continue;
                }

                warnings.Add($"Skipping unsupported endpoint scheme in '{value}'.");
                targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                    Stage = "additional-endpoints",
                    Action = "rejected",
                    Reason = "unsupported-scheme",
                    Target = value,
                    Service = scheme,
                    Message = $"Scheme '{scheme}' is not supported for certificate inventory capture."
                });
                continue;
            }

            if (TryParseHostAndPort(value, out var hostWithPort, out var parsedPort)) {
                if (TryCreateMailTargetFromPort(hostWithPort, parsedPort, out var targetByPort)) {
                    targetByPort!.TargetOrigins.Add(TargetOriginAdditionalEndpoint);
                    AddMailTarget(mailTargets, targetByPort!);
                } else {
                    AddHttpsTarget(
                        httpsTargets,
                        httpsTargetOriginsByEndpointKey,
                        BuildHttpsUrl($"{hostWithPort}:{parsedPort}", options.HttpsPort),
                        TargetOriginAdditionalEndpoint);
                }
            } else {
                if (EndpointHostNormalizer.TryNormalize(value, out string normalizedHost) &&
                    normalizedHost.Length > 0) {
                    AddHttpsTarget(
                        httpsTargets,
                        httpsTargetOriginsByEndpointKey,
                        BuildHttpsUrl(normalizedHost, options.HttpsPort),
                        TargetOriginAdditionalEndpoint);
                } else {
                    warnings.Add($"Skipping invalid endpoint '{value}'.");
                    targetDecisionDiagnostics.Add(new TargetDecisionDiagnosticEntry {
                        Stage = "additional-endpoints",
                        Action = "rejected",
                        Reason = "invalid-endpoint",
                        Target = value,
                        Message = "Brackets are valid only around an IPv6 literal endpoint host."
                    });
                }
            }
        }
    }

    private static bool TryCreateFtpTlsTargetFromScheme(Uri uri, out FtpTlsEndpointTarget? target) {
        target = null;
        string scheme = uri.Scheme.ToLowerInvariant();
        FtpTlsMode mode;
        int defaultPort;
        string normalizedScheme;
        string service;
        switch (scheme) {
            case "ftps":
                mode = FtpTlsMode.Implicit;
                defaultPort = 990;
                normalizedScheme = "ftps";
                service = "FTPS-IMPLICIT";
                break;
            case "ftps-explicit":
            case "ftpes":
            case "ftp+tls":
                mode = FtpTlsMode.Explicit;
                defaultPort = 21;
                normalizedScheme = "ftps-explicit";
                service = "FTPS-EXPLICIT";
                break;
            default:
                return false;
        }

        string host = EndpointHostNormalizer.Normalize(uri.Host);
        bool hasExplicitPort = TryGetExplicitUriPort(uri, out int explicitPort);
        if (host.Length == 0 ||
            (hasExplicitPort && (explicitPort < 1 || explicitPort > 65535)) ||
            (!hasExplicitPort && !uri.IsDefaultPort && (uri.Port < 1 || uri.Port > 65535))) {
            return false;
        }
        target = new FtpTlsEndpointTarget {
            Host = host,
            Port = hasExplicitPort ? explicitPort : (uri.IsDefaultPort ? defaultPort : uri.Port),
            Mode = mode,
            Scheme = normalizedScheme,
            Service = service
        };
        return true;
    }

    private static bool IsFtpTlsScheme(string scheme) {
        return scheme == "ftps" ||
               scheme == "ftps-explicit" ||
               scheme == "ftpes" ||
               scheme == "ftp+tls";
    }

    private static bool TryGetExplicitUriPort(Uri uri, out int port) {
        port = 0;
        string original = uri.OriginalString;
        int schemeSeparator = original.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator < 0) {
            return false;
        }
        int authorityStart = schemeSeparator + 3;
        int authorityEnd = original.IndexOfAny(new[] { '/', '?', '#' }, authorityStart);
        string authority = authorityEnd < 0
            ? original.Substring(authorityStart)
            : original.Substring(authorityStart, authorityEnd - authorityStart);
        int userInfoSeparator = authority.LastIndexOf('@');
        if (userInfoSeparator >= 0) {
            authority = authority.Substring(userInfoSeparator + 1);
        }

        int portSeparator;
        if (authority.StartsWith("[", StringComparison.Ordinal)) {
            int bracket = authority.IndexOf(']');
            portSeparator = bracket >= 0 && bracket + 1 < authority.Length && authority[bracket + 1] == ':'
                ? bracket + 1
                : -1;
        } else {
            portSeparator = authority.LastIndexOf(':');
        }
        if (portSeparator < 0 || portSeparator + 1 >= authority.Length) {
            return false;
        }
        return int.TryParse(authority.Substring(portSeparator + 1), out port);
    }

    private static bool TryCreateMailTargetFromScheme(Uri uri, CertificateInventoryCaptureOptions options, out MailEndpointTarget? target) {
        target = null;
        var host = EndpointHostNormalizer.Normalize(uri.Host);
        if (string.IsNullOrWhiteSpace(host)) {
            return false;
        }
        var scheme = uri.Scheme.ToLowerInvariant();
        if (scheme == "smtp") {
            target = new MailEndpointTarget {
                Host = host,
                Port = uri.IsDefaultPort ? options.SmtpPort : uri.Port,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-STARTTLS",
                Scheme = "smtp",
                ChainSource = "mailtls-starttls"
            };
            return true;
        }
        if (scheme == "submission") {
            target = new MailEndpointTarget {
                Host = host,
                Port = uri.IsDefaultPort ? options.SubmissionPort : uri.Port,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-SUBMISSION-STARTTLS",
                Scheme = "submission",
                ChainSource = "mailtls-starttls"
            };
            return true;
        }
        if (scheme == "imap" || scheme == "imaps") {
            target = new MailEndpointTarget {
                Host = host,
                Port = uri.IsDefaultPort ? options.ImapPort : uri.Port,
                Protocol = MailTlsAnalysis.MailProtocol.Imap,
                Service = "IMAPS",
                Scheme = "imaps",
                ChainSource = "mailtls-directtls"
            };
            return true;
        }
        if (scheme == "pop3" || scheme == "pop3s") {
            target = new MailEndpointTarget {
                Host = host,
                Port = uri.IsDefaultPort ? options.Pop3Port : uri.Port,
                Protocol = MailTlsAnalysis.MailProtocol.Pop3,
                Service = "POP3S",
                Scheme = "pop3s",
                ChainSource = "mailtls-directtls"
            };
            return true;
        }
        return false;
    }

    private static bool TryCreateMailTargetFromPort(string host, int port, out MailEndpointTarget? target) {
        target = null;
        var normalized = EndpointHostNormalizer.Normalize(host);
        if (string.IsNullOrWhiteSpace(normalized)) {
            return false;
        }

        if (port == 25) {
            target = new MailEndpointTarget {
                Host = normalized,
                Port = port,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-STARTTLS",
                Scheme = "smtp",
                ChainSource = "mailtls-starttls"
            };
            return true;
        }
        if (port == 587) {
            target = new MailEndpointTarget {
                Host = normalized,
                Port = port,
                Protocol = MailTlsAnalysis.MailProtocol.Smtp,
                Service = "SMTP-SUBMISSION-STARTTLS",
                Scheme = "submission",
                ChainSource = "mailtls-starttls"
            };
            return true;
        }
        if (port == 993) {
            target = new MailEndpointTarget {
                Host = normalized,
                Port = port,
                Protocol = MailTlsAnalysis.MailProtocol.Imap,
                Service = "IMAPS",
                Scheme = "imaps",
                ChainSource = "mailtls-directtls"
            };
            return true;
        }
        if (port == 995) {
            target = new MailEndpointTarget {
                Host = normalized,
                Port = port,
                Protocol = MailTlsAnalysis.MailProtocol.Pop3,
                Service = "POP3S",
                Scheme = "pop3s",
                ChainSource = "mailtls-directtls"
            };
            return true;
        }
        return false;
    }

    private static bool TryParseHostAndPort(string value, out string host, out int port) {
        host = string.Empty;
        port = 0;
        var idx = value.LastIndexOf(':');
        if (idx <= 0 || idx >= value.Length - 1) {
            return false;
        }
        var maybeHost = value.Substring(0, idx).Trim();
        var maybePort = value.Substring(idx + 1).Trim();
        if (!int.TryParse(maybePort, out var parsed) || parsed < 1 || parsed > 65535) {
            return false;
        }
        if (string.IsNullOrWhiteSpace(maybeHost)) {
            return false;
        }
        if (!EndpointHostNormalizer.TryNormalize(maybeHost, out string normalizedHost) ||
            normalizedHost.Length == 0) {
            return false;
        }
        host = normalizedHost;
        port = parsed;
        return true;
    }

    private static async Task<IReadOnlyList<string>> ResolveMxHostsAsync(string domain, DnsConfiguration dnsConfiguration, int maxMxHostsPerDomain, CancellationToken cancellationToken) {
        var answers = await dnsConfiguration.QueryDNS(domain, DnsRecordType.MX, cancellationToken: cancellationToken).ConfigureAwait(false);
        var hosts = new List<string>();
        foreach (var answer in answers) {
            if (TryExtractMxHost(answer.DataRaw, out var host) ||
                TryExtractMxHost(answer.Data, out host)) {
                hosts.Add(host);
            }
        }

        var distinct = hosts
            .Where(h => !string.IsNullOrWhiteSpace(h) && IsSupportedMxHost(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(h => h, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (maxMxHostsPerDomain > 0 && distinct.Count > maxMxHostsPerDomain) {
            distinct = distinct.Take(maxMxHostsPerDomain).ToList();
        }
        return distinct;
    }

    internal static bool TryExtractMxHost(string? rawValue, out string host) {
        host = string.Empty;
        if (string.IsNullOrWhiteSpace(rawValue)) {
            return false;
        }

        var parts = rawValue!
            .Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) {
            return false;
        }

        var candidate = parts.Length == 1 ? parts[0].Trim() : parts[parts.Length - 1].Trim();
        return TryNormalizeMxHostCandidate(candidate, out host);
    }

    private static bool TryNormalizeMxHostCandidate(string? candidate, out string host) {
        host = string.Empty;
        if (string.IsNullOrWhiteSpace(candidate)) {
            return false;
        }

        var normalized = candidate!.Trim().TrimEnd('.');
        if (!IsSupportedMxHost(normalized)) {
            return false;
        }

        host = normalized;
        return true;
    }

    private static bool IsSupportedMxHost(string value) {
        if (string.IsNullOrWhiteSpace(value)) {
            return false;
        }

        var normalized = value.Trim().TrimEnd('.');
        if (normalized.Length == 0) {
            return false;
        }

        if (string.Equals(normalized, ".", StringComparison.Ordinal) ||
            string.Equals(normalized, "-", StringComparison.Ordinal)) {
            return false;
        }

        if (int.TryParse(normalized, NumberStyles.Integer, CultureInfo.InvariantCulture, out _)) {
            return false;
        }

        if (System.Net.IPAddress.TryParse(normalized, out _)) {
            return false;
        }

        if (normalized.IndexOfAny(new[] { ' ', '\t', '\r', '\n', '/', '\\', '@' }) >= 0) {
            return false;
        }

        return true;
    }

}
