using System;
using System.Collections.Generic;
using System.IO;

namespace DomainDetective {
    /// <summary>
    /// Provides utilities for working with the public suffix list.
    /// </summary>
    internal class PublicSuffixList {
        private readonly HashSet<string> _exactRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _wildcardRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _exceptionRules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private PublicSuffixList() { }

        /// <summary>
        /// Loads the public suffix list from the specified file.
        /// </summary>
        public static PublicSuffixList Load(string filePath) {
            var list = new PublicSuffixList();
            if (!File.Exists(filePath)) {
                return list;
            }

            foreach (var line in File.ReadLines(filePath)) {
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
        /// Determines whether the provided domain is a public suffix.
        /// </summary>
        public bool IsPublicSuffix(string domain) {
            if (string.IsNullOrWhiteSpace(domain)) {
                return false;
            }

            domain = domain.Trim().Trim('.').ToLowerInvariant();
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
    }
}
