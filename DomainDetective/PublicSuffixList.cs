using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective {
    /// <summary>
    /// Provides utilities for working with the public suffix list.
    /// </summary>
    internal class PublicSuffixList {
        private readonly HashSet<string> _exactRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _wildcardRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _exceptionRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private const int MaxLabelLength = 63;

        internal PublicSuffixList() { }

        /// <summary>
        /// Loads the public suffix list from the specified file.
        /// </summary>
        public static PublicSuffixList Load(string filePath) {
            if (!File.Exists(filePath)) {
                return new PublicSuffixList();
            }

            using var stream = File.OpenRead(filePath);
            return Load(stream);
        }

        /// <summary>
        /// Loads the public suffix list from an open <see cref="Stream"/>.
        /// </summary>
        /// <param name="stream">Stream containing the list data.</param>
        /// <returns>An initialized <see cref="PublicSuffixList"/> instance.</returns>
        public static PublicSuffixList Load(Stream stream) {
            var list = new PublicSuffixList();
            using var reader = new StreamReader(stream);
            while (reader.ReadLine() is { } line) {
                var trimmed = line.Trim();
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("//")) {
                    continue;
                }

                if (trimmed.StartsWith("!")) {
                    list._exceptionRules.Add(Canonicalize(trimmed.Substring(1)));
                } else if (trimmed.StartsWith("*.", StringComparison.Ordinal)) {
                    list._wildcardRules.Add(Canonicalize(trimmed.Substring(2)));
                } else {
                    list._exactRules.Add(Canonicalize(trimmed));
                }
            }

            return list;
        }

        /// <summary>
        /// Downloads and loads the public suffix list from the given URL.
        /// </summary>
        /// <param name="url">HTTP or HTTPS address of the list.</param>
        /// <returns>A task representing the asynchronous operation.</returns>
        public static async Task<PublicSuffixList> LoadFromUrlAsync(string url) {
            var client = SharedHttpClient.Instance;
            using var stream = await client.GetStreamAsync(url);
            return Load(stream);
        }

        /// <summary>
        /// Determines whether the provided domain is a public suffix.
        /// </summary>
        public bool IsPublicSuffix(string domain) {
            if (string.IsNullOrWhiteSpace(domain)) {
                return false;
            }

            var clean = Canonicalize(domain);
            return clean.Split('.').Length == GetPublicSuffixLabelCount(clean);
        }

        public string GetRegistrableDomain(string domain) {
            if (string.IsNullOrWhiteSpace(domain)) {
                throw new ArgumentNullException(nameof(domain));
            }

            var clean = Canonicalize(domain);
            var parts = clean.Split('.');
            if (parts.Length <= 1) {
                return clean;
            }

            var suffixLabels = GetPublicSuffixLabelCount(clean);
            return string.Join(".", parts.Skip(Math.Max(0, parts.Length - suffixLabels - 1)));
        }

        // Exceptions prevail over all other rules; otherwise use the longest match.
        // A wildcard consumes exactly one label, and the implicit default rule is '*'.
        private int GetPublicSuffixLabelCount(string domain) {
            var labels = domain.Split('.');
            var longest = 1;
            for (var i = 0; i < labels.Length; i++) {
                var candidate = string.Join(".", labels.Skip(i));
                var count = labels.Length - i;
                if (_exceptionRules.Contains(candidate)) {
                    return count - 1;
                }
                if (_exactRules.Contains(candidate)) {
                    longest = Math.Max(longest, count);
                }
                if (i > 0 && _wildcardRules.Contains(candidate)) {
                    longest = Math.Max(longest, count + 1);
                }
            }
            return longest;
        }

        private static string Canonicalize(string domain) {
            var clean = DomainHelper.ValidateIdn(domain.Trim().TrimEnd('.')).ToLowerInvariant();
            ValidateLabels(clean);
            if (clean.Split('.').Any(label => label.Length == 0)) {
                throw new ArgumentException("Domain labels cannot be empty.", nameof(domain));
            }
            return clean;
        }

        private static void ValidateLabels(string domain) {
            foreach (var label in domain.Split('.')) {
                if (label.Length > MaxLabelLength) {
                    throw new ArgumentException(
                        $"Domain label '{label}' exceeds {MaxLabelLength} characters.", nameof(domain));
                }
            }
        }
    }
}
