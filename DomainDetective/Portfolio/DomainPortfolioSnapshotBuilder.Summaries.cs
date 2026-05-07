using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace DomainDetective;

public static partial class DomainPortfolioSnapshotBuilder {
    private static readonly string[] MxHostFactKeys = { "Hosts", "MxHosts", "MailServers", "Exchanges" };

    private static DomainRegistrationPortfolioSummary BuildRegistrationSummary(DomainPortfolioSnapshot snapshot, SnapshotFactLookup facts) {
        var expiresAt = facts.Date("WHOIS", "Expires", "ExpirationDate", "ExpiryDate", "RegistryExpiryDate", "RegistrarRegistrationExpirationDate")
            ?? facts.Date("RDAP", "ExpiresAt", "ExpirationDate", "ExpiryDate");
        return new DomainRegistrationPortfolioSummary {
            Registrar = facts.String("WHOIS", "Registrar", "RegistrarName")
                ?? facts.String("RDAP", "Registrar", "RegistrarName"),
            CreatedAtUtc = facts.Date("WHOIS", "Created", "CreationDate", "RegisteredAt", "RegistrationDate")
                ?? facts.Date("RDAP", "CreatedAt", "RegistrationDate"),
            UpdatedAtUtc = facts.Date("WHOIS", "Updated", "UpdatedDate", "LastUpdated")
                ?? facts.Date("RDAP", "UpdatedAt", "UpdatedDate"),
            ExpiresAtUtc = expiresAt,
            DaysToExpiry = DaysBetween(snapshot.CapturedAtUtc, expiresAt),
            Statuses = facts.List("WHOIS", "Status", "Statuses", "DomainStatus")
                .Concat(facts.List("RDAP", "Status", "Statuses", "DomainStatus"))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
                .ToList(),
            NameServers = facts.List("WHOIS", "NameServers", "NameServer")
                .Concat(facts.List("RDAP", "NameServers", "NameServer"))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
                .ToList()
        };
    }

    private static DomainDnsPortfolioSummary BuildDnsSummary(SnapshotFactLookup facts)
        => new() {
            NameServers = facts.List("NS", "NameServers", "Hosts", "Servers"),
            MxHosts = facts.List("MX", MxHostFactKeys),
            IPv4Addresses = facts.List("APEXADDRESS", "IPv4Addresses", "Ipv4Addresses", "ARecords", "Addresses"),
            IPv6Addresses = facts.List("APEXADDRESS", "IPv6Addresses", "Ipv6Addresses", "AAAARecords"),
            DnssecEnabled = facts.Bool("DNSSEC", "ChainValid", "IsSigned", "HasDnssec", "DnssecEnabled"),
            CaaPresent = facts.Bool("CAA", "CaaRecordExists", "RecordExists", "HasCaaRecords", "HasRecords")
        };

    private static DomainCertificatePortfolioSummary BuildCertificateSummary(DomainPortfolioSnapshot snapshot, SnapshotFactLookup facts) {
        var notAfter = facts.Date("CERT", "NotAfter", "NotAfterUtc", "ValidTo", "ExpiresAtUtc", "ExpirationDate");
        return new DomainCertificatePortfolioSummary {
            Fingerprint = facts.String("CERT", "Fingerprint", "Thumbprint", "CertificateThumbprint", "Sha256Fingerprint", "Sha1Thumbprint"),
            Subject = facts.String("CERT", "Subject", "SubjectName", "SubjectCommonName"),
            Issuer = facts.String("CERT", "Issuer", "IssuerName", "IssuerCommonName", "IssuerOrganization"),
            NotBeforeUtc = facts.Date("CERT", "NotBefore", "NotBeforeUtc", "ValidFrom"),
            NotAfterUtc = notAfter,
            DaysToExpiry = DaysBetween(snapshot.CapturedAtUtc, notAfter),
            Valid = facts.Bool("CERT", "Valid", "IsValid", "CertificateValid"),
            HostnameMatch = facts.Bool("CERT", "HostnameMatch", "NameMatches", "SubjectMatches")
        };
    }

    private static DomainMailPortfolioSummary BuildMailSummary(SnapshotFactLookup facts)
        => new() {
            MxHosts = facts.List("MX", MxHostFactKeys),
            Provider = facts.String("MX", "ProviderPrimary", "MailProvider", "Provider")
                ?? facts.String("DNSINVENTORY", "MailProvider", "MailProviderName"),
            SpfRecord = facts.String("SPF", "SpfRecord", "Record", "RecordValue"),
            SpfAllMechanism = facts.String("SPF", "AllMechanism", "All", "AllMechanismValue"),
            DmarcRecord = facts.String("DMARC", "DmarcRecord", "Record", "RecordValue"),
            DmarcPolicy = facts.String("DMARC", "PolicyShort", "Policy"),
            MtaStsMode = facts.String("MTASTS", "Mode", "PolicyMode"),
            TlsRptRecord = facts.String("TLSRPT", "TlsRptRecord", "Record", "RecordValue")
        };

    private static DomainWebsitePortfolioSummary BuildWebsiteSummary(SnapshotFactLookup facts)
        => new() {
            StatusCode = facts.Int("HTTP", "StatusCode", "ResponseStatusCode", "HttpStatusCode"),
            FinalUrl = facts.String("HTTP", "FinalUrl", "EffectiveUrl", "Url"),
            UsesHttps = facts.Bool("HTTP", "UsesHttps", "IsHttps", "Https"),
            SecurityTxtPresent = facts.Bool("SECURITYTXT", "Present", "Exists", "SecurityTxtExists", "Found"),
            RobotsTxtPresent = facts.Bool("ROBOTS", "Present", "Exists", "RobotsTxtExists", "Found")
        };

    private static int? DaysBetween(DateTimeOffset capturedAtUtc, DateTimeOffset? futureUtc) {
        if (!futureUtc.HasValue) return null;
        return (int)Math.Floor((futureUtc.Value.ToUniversalTime() - capturedAtUtc.ToUniversalTime()).TotalDays);
    }

    private sealed class SnapshotFactLookup {
        private readonly Dictionary<string, Dictionary<string, DomainPortfolioFact>> _sections;

        public SnapshotFactLookup(DomainPortfolioSnapshot snapshot) {
            _sections = (snapshot.Sections ?? new List<DomainPortfolioSection>())
                .Where(static section => section != null && !string.IsNullOrWhiteSpace(section.Key))
                .GroupBy(static section => section.Key, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(
                    static group => group.Key,
                    static group => {
                        var section = DomainPortfolioUtilities.SinglePortfolioItem(group, "section", group.Key);
                        return (section.Facts ?? new List<DomainPortfolioFact>())
                            .Where(static fact => fact != null && !string.IsNullOrWhiteSpace(fact.Key))
                            .GroupBy(static fact => fact.Key, StringComparer.OrdinalIgnoreCase)
                            .ToDictionary(
                                static factGroup => factGroup.Key,
                                static factGroup => DomainPortfolioUtilities.SinglePortfolioItem(factGroup, "fact", factGroup.Key),
                                StringComparer.OrdinalIgnoreCase);
                    },
                    StringComparer.OrdinalIgnoreCase);
        }

        public string? String(string sectionKey, params string[] keys) {
            return keys
                .Select(key => Fact(sectionKey, key)?.Value)
                .FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value));
        }

        public List<string> List(string sectionKey, params string[] keys) {
            var fact = keys
                .Select(key => Fact(sectionKey, key))
                .FirstOrDefault(static item => !string.IsNullOrWhiteSpace(item?.Value));

            if (fact == null || string.IsNullOrWhiteSpace(fact.Value)) return new List<string>();
            var values = fact.Kind == DomainPortfolioFactKind.Collection
                ? SplitCollectionValue(fact.Value)
                : new List<string> { fact.Value.Trim() };

            return values
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static item => item, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        public bool? Bool(string sectionKey, params string[] keys) {
            var value = String(sectionKey, keys);
            if (string.IsNullOrWhiteSpace(value)) return null;
            if (bool.TryParse(value, out var parsed)) return parsed;
            if (string.Equals(value, "1", StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(value, "0", StringComparison.OrdinalIgnoreCase)) return false;
            return null;
        }

        public int? Int(string sectionKey, params string[] keys) {
            var value = String(sectionKey, keys);
            if (string.IsNullOrWhiteSpace(value)) {
                return null;
            }

            if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)) return parsed;
            return null;
        }

        public DateTimeOffset? Date(string sectionKey, params string[] keys) {
            var value = String(sectionKey, keys);
            if (string.IsNullOrWhiteSpace(value)) return null;
            if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed)) {
                return parsed.ToUniversalTime();
            }

            return null;
        }

        private DomainPortfolioFact? Fact(string sectionKey, string key)
            => _sections.TryGetValue(sectionKey, out var section) && section.TryGetValue(key, out var fact)
                ? fact
                : null;
    }
}
