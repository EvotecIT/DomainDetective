using System;
using System.Collections.Generic;
using System.IO;

namespace DomainDetective;

/// <summary>
/// Provides lookup sets for email validation heuristics.
/// </summary>
public static class EmailValidationData {
    private const string DisposableResource = "DomainDetective.email_disposable_domains.txt";
    private const string RoleResource = "DomainDetective.email_role_accounts.txt";
    private const string FreeResource = "DomainDetective.email_free_providers.txt";
    private const string B2CResource = "DomainDetective.email_b2c_providers.txt";

    private static readonly Lazy<HashSet<string>> _disposableDomains = new(() => LoadSet(DisposableResource));
    private static readonly Lazy<HashSet<string>> _roleAccounts = new(() => LoadSet(RoleResource));
    private static readonly Lazy<HashSet<string>> _freeProviders = new(() => LoadSet(FreeResource));
    private static readonly Lazy<HashSet<string>> _b2cProviders = new(() => LoadSet(B2CResource));
    private static readonly Dictionary<string, CachedSet> _fileCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _cacheLock = new();

    /// <summary>Returns true when <paramref name="domain"/> is a known disposable provider.</summary>
    public static bool IsDisposableDomain(string? domain, string? overridePath = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
            return false;
        }
        var set = GetSet(overridePath, _disposableDomains);
        return IsDomainOrSubdomain(domain, set);
    }

    /// <summary>Returns true when <paramref name="localPart"/> matches a role account.</summary>
    public static bool IsRoleAccount(string? localPart, string? overridePath = null) {
        if (string.IsNullOrWhiteSpace(localPart)) {
            return false;
        }
        var set = GetSet(overridePath, _roleAccounts);
        return set.Contains(localPart.Trim());
    }

    /// <summary>Returns true when <paramref name="domain"/> is a known free provider.</summary>
    public static bool IsFreeProvider(string? domain, string? overridePath = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
            return false;
        }
        var set = GetSet(overridePath, _freeProviders);
        return IsDomainOrSubdomain(domain, set);
    }

    /// <summary>Returns true when <paramref name="domain"/> is a known B2C provider.</summary>
    public static bool IsB2CProvider(string? domain, string? overridePath = null) {
        if (string.IsNullOrWhiteSpace(domain)) {
            return false;
        }
        var set = GetSet(overridePath, _b2cProviders);
        return IsDomainOrSubdomain(domain, set);
    }

    private static bool IsDomainOrSubdomain(string domain, HashSet<string> set) {
        var clean = domain.Trim().Trim('.').ToLowerInvariant();
        if (set.Contains(clean)) {
            return true;
        }
        var idx = clean.IndexOf('.', StringComparison.Ordinal);
        while (idx > 0 && idx < clean.Length - 1) {
            var suffix = clean[(idx + 1)..];
            if (set.Contains(suffix)) {
                return true;
            }
            idx = clean.IndexOf('.', idx + 1);
        }
        return false;
    }

    private static HashSet<string> LoadSet(string resourceName) {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var assembly = typeof(EmailValidationData).Assembly;
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null) {
            return set;
        }
        using var reader = new StreamReader(stream);
        string? line;
        while ((line = reader.ReadLine()) != null) {
            line = line.Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) {
                continue;
            }
            set.Add(line);
        }
        return set;
    }

    private static HashSet<string> GetSet(string? overridePath, Lazy<HashSet<string>> builtin) {
        var custom = TryLoadSetFromFile(overridePath);
        return custom ?? builtin.Value;
    }

    private static HashSet<string>? TryLoadSetFromFile(string? path) {
        if (string.IsNullOrWhiteSpace(path)) {
            return null;
        }
        if (!File.Exists(path)) {
            return null;
        }

        var fullPath = Path.GetFullPath(path);
        var lastWrite = File.GetLastWriteTimeUtc(fullPath);

        lock (_cacheLock) {
            if (_fileCache.TryGetValue(fullPath, out var cached) && cached.LastWriteUtc == lastWrite) {
                return cached.Set;
            }

            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var reader = new StreamReader(fullPath);
            string? line;
            while ((line = reader.ReadLine()) != null) {
                line = line.Trim();
                if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal)) {
                    continue;
                }
                set.Add(line);
            }

            _fileCache[fullPath] = new CachedSet(lastWrite, set);
            return set;
        }
    }

    private sealed class CachedSet {
        public CachedSet(DateTime lastWriteUtc, HashSet<string> set) {
            LastWriteUtc = lastWriteUtc;
            Set = set;
        }

        public DateTime LastWriteUtc { get; }
        public HashSet<string> Set { get; }
    }
}
