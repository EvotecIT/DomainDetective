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

    private static string BuildMailTargetLabel(MailEndpointTarget target) {
        return $"{target.Scheme}://{target.Host}:{target.Port}";
    }

    private static string BuildEndpointKey(string host, int port, string service) {
        return CertificateInventoryEndpointKey.Build(host, null, port, service, null);
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
        if (entry.IsReachable) {
            return false;
        }
        if (!string.IsNullOrWhiteSpace(entry.CertificateThumbprint)) {
            return false;
        }

        var failureReason = entry.FailureReason?.Trim();
        if (string.IsNullOrWhiteSpace(failureReason)) {
            return false;
        }

        return failureReason.Contains("FailureKind:Cancelled", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("FailureKind:Timeout", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("FailureKind:TlsHandshake", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("HttpRequestError:NameResolutionError", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("HttpRequestError:ConnectionError", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("HttpRequestError:SecureConnectionError", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("TLS Handshake Failure", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:HostNotFound", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:NoData", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:TryAgain", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:TimedOut", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:ConnectionRefused", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:ConnectionReset", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:ConnectionAborted", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:HostUnreachable", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:NetworkUnreachable", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("SocketError:NetworkDown", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("No such host is known", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("actively refused", StringComparison.OrdinalIgnoreCase) ||
               failureReason.Contains("forcibly closed by the remote host", StringComparison.OrdinalIgnoreCase);
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

        if (options.ReuseRecentSnapshotEntries &&
            options.RecentSnapshotTtl > TimeSpan.Zero &&
            cachedEntry.CapturedAtUtc >= now - options.RecentSnapshotTtl &&
            ShouldReuseCachedSuccessEntry(cachedEntry.Entry, now, options.ReprobeExpiringWithinDays)) {
            return true;
        }

        if (options.ReuseRecentFailureSnapshotEntries &&
            options.RecentFailureSnapshotTtl > TimeSpan.Zero &&
            cachedEntry.CapturedAtUtc >= now - options.RecentFailureSnapshotTtl &&
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
                pair => new RecentInventoryEndpointEntry {
                    Entry = pair.Value,
                    CapturedAtUtc = capturedAtUtc
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
                var host = !string.IsNullOrWhiteSpace(entry.ResolvedHost) ? entry.ResolvedHost! : entry.Host;
                if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(entry.Service) || entry.Port <= 0) {
                    continue;
                }
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
        HashSet<string> httpsTargets,
        Dictionary<string, MailEndpointTarget> mailTargets,
        List<string> warnings,
        IReadOnlyDictionary<string, RecentInventoryEndpointEntry>? recentByEndpoint,
        int reprobeExpiringWithinDays) {
        if (options.MaxTargets <= 0) {
            return;
        }

        var totalTargets = httpsTargets.Count + mailTargets.Count;
        if (totalTargets <= options.MaxTargets) {
            return;
        }

        var originalHttps = httpsTargets.Count;
        var originalMail = mailTargets.Count;
        var limit = options.MaxTargets;
        ResolveTargetBudget(
            originalHttps,
            originalMail,
            limit,
            out var allowedHttps,
            out var allowedMail);

        if (originalMail > allowedMail) {
            var keptMail = mailTargets.Values
                .OrderByDescending(target => ComputeMailTargetPriority(target, recentByEndpoint, reprobeExpiringWithinDays))
                .ThenBy(target => ResolvePrioritySortDays(target, recentByEndpoint))
                .ThenBy(target => target.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(target => target.Port)
                .ThenBy(target => target.Service, StringComparer.OrdinalIgnoreCase)
                .Take(allowedMail)
                .ToList();

            mailTargets.Clear();
            foreach (var target in keptMail) {
                AddMailTarget(mailTargets, target);
            }
        }

        if (originalHttps > allowedHttps) {
            var keptHttps = httpsTargets
                .OrderByDescending(target => ComputeHttpsTargetPriority(target, recentByEndpoint, reprobeExpiringWithinDays))
                .ThenBy(target => ResolvePrioritySortDays(target, recentByEndpoint))
                .ThenBy(target => target, StringComparer.OrdinalIgnoreCase)
                .Take(allowedHttps)
                .ToList();

            httpsTargets.Clear();
            foreach (var target in keptHttps) {
                httpsTargets.Add(target);
            }
        }

        warnings.Add($"Probe target list capped from {totalTargets} to {options.MaxTargets} by MaxTargets (HTTPS: {originalHttps}->{httpsTargets.Count}, Mail: {originalMail}->{mailTargets.Count}).");
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
        Dictionary<string, MailEndpointTarget> mailTargets,
        List<string> warnings) {
        foreach (var raw in options.AdditionalEndpoints) {
            if (string.IsNullOrWhiteSpace(raw)) {
                continue;
            }
            var value = raw.Trim();
            if (value.IndexOf("://", StringComparison.Ordinal) >= 0) {
                if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host)) {
                    warnings.Add($"Skipping invalid endpoint '{value}'.");
                    continue;
                }

                var scheme = uri.Scheme.ToLowerInvariant();
                if (scheme == Uri.UriSchemeHttp || scheme == Uri.UriSchemeHttps) {
                    var builder = new UriBuilder(uri) {
                        Scheme = Uri.UriSchemeHttps,
                        Port = uri.IsDefaultPort ? options.HttpsPort : uri.Port
                    };
                    httpsTargets.Add(builder.Uri.ToString());
                    continue;
                }

                if (TryCreateMailTargetFromScheme(uri, options, out var target)) {
                    AddMailTarget(mailTargets, target!);
                    continue;
                }

                warnings.Add($"Skipping unsupported endpoint scheme in '{value}'.");
                continue;
            }

            if (TryParseHostAndPort(value, out var hostWithPort, out var parsedPort)) {
                if (TryCreateMailTargetFromPort(hostWithPort, parsedPort, out var targetByPort)) {
                    AddMailTarget(mailTargets, targetByPort!);
                } else {
                    httpsTargets.Add(BuildHttpsUrl($"{hostWithPort}:{parsedPort}", options.HttpsPort));
                }
            } else {
                httpsTargets.Add(BuildHttpsUrl(value, options.HttpsPort));
            }
        }
    }

    private static bool TryCreateMailTargetFromScheme(Uri uri, CertificateInventoryCaptureOptions options, out MailEndpointTarget? target) {
        target = null;
        var host = uri.Host.Trim().TrimEnd('.');
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
        var normalized = host.Trim().TrimEnd('.');
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
        host = maybeHost;
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
