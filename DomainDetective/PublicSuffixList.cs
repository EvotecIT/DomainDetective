using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Provides utilities for working with the public suffix list.
    /// </summary>
    internal class PublicSuffixList {
        private readonly HashSet<string> _exactRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _wildcardRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _exceptionRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static readonly IdnMapping _idn = new();
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
                    list._exceptionRules.Add(trimmed.Substring(1));
                } else if (trimmed.StartsWith("*.", StringComparison.Ordinal)) {
                    list._wildcardRules.Add(trimmed.Substring(2));
                } else {
                    list._exactRules.Add(trimmed);
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

            domain = _idn.GetAscii(domain.Trim().Trim('.'));
            ValidateLabels(domain);
            domain = domain.ToLowerInvariant();
            if (_exceptionRules.Contains(domain)) {
                return false;
            }
            if (_exactRules.Contains(domain)) {
                return true;
            }

            foreach (var rule in _wildcardRules) {
                if (domain.EndsWith("." + rule, StringComparison.OrdinalIgnoreCase)) {
                    var prefixLength = domain.Length - rule.Length - 1;
                    if (prefixLength > 0 && domain.IndexOf('.', 0, prefixLength) == -1) {
                        // only one label before rule
                        return true;
                    }
                    if (prefixLength > 0) {
                        return true;
                    }
                }
            }

            return false;
        }

        public string GetRegistrableDomain(string domain) {
            if (string.IsNullOrWhiteSpace(domain)) {
                throw new ArgumentNullException(nameof(domain));
            }

            var clean = _idn.GetAscii(domain.Trim().Trim('.')).ToLowerInvariant();
            var parts = clean.Split('.');
            if (parts.Length <= 1) {
                return clean;
            }

            for (int i = 0; i < parts.Length; i++) {
                var candidate = string.Join(".", parts.Skip(i));
                if (IsPublicSuffix(candidate)) {
                    if (i == 0) {
                        return clean;
                    }

                    return string.Join(".", parts.Skip(i - 1));
                }
            }

            return string.Join(".", parts.Skip(parts.Length - 2));
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
