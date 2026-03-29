using DomainDetective.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public partial class TyposquattingAnalysis
{
    private static readonly Dictionary<char, char[]> _homoglyphs = new()
    {
        ['0'] = new[] { 'o' },
        ['1'] = new[] { 'l', 'i' },
        ['3'] = new[] { 'e' },
        ['5'] = new[] { 's' },
        ['8'] = new[] { 'b' },
        ['a'] = new[] { '@', '4' },
        ['b'] = new[] { '8' },
        ['e'] = new[] { '3' },
        ['g'] = new[] { '9' },
        ['i'] = new[] { '1', 'l' },
        ['l'] = new[] { '1', 'i' },
        ['o'] = new[] { '0' },
        ['s'] = new[] { '5', '$' },
        ['z'] = new[] { '2' }
    };

    private static readonly Dictionary<char, char> _latinToCyrillic = new()
    {
        ['a'] = '\u0430',
        ['c'] = '\u0441',
        ['e'] = '\u0435',
        ['i'] = '\u0456',
        ['j'] = '\u0458',
        ['o'] = '\u043e',
        ['p'] = '\u0440',
        ['s'] = '\u0455',
        ['x'] = '\u0445',
        ['y'] = '\u0443'
    };

    private static readonly Dictionary<char, string> _keyboardNeighbors = new()
    {
        ['1'] = "2q",
        ['2'] = "13wq",
        ['3'] = "24ew",
        ['4'] = "35re",
        ['5'] = "46tr",
        ['6'] = "57yt",
        ['7'] = "68uy",
        ['8'] = "79iu",
        ['9'] = "80oi",
        ['0'] = "9po",
        ['a'] = "qwsz",
        ['b'] = "vghn",
        ['c'] = "xdfv",
        ['d'] = "serfcx",
        ['e'] = "wsdfr",
        ['f'] = "drtgvc",
        ['g'] = "ftyhbv",
        ['h'] = "gyujnb",
        ['i'] = "ujko",
        ['j'] = "huikmn",
        ['k'] = "jiolm",
        ['l'] = "kop",
        ['m'] = "njk",
        ['n'] = "bhjm",
        ['o'] = "iklp",
        ['p'] = "ol",
        ['q'] = "12wa",
        ['r'] = "edft5",
        ['s'] = "awedxz",
        ['t'] = "rfgy6",
        ['u'] = "yhji7",
        ['v'] = "cfgb",
        ['w'] = "qase23",
        ['x'] = "zsdc",
        ['y'] = "tghu7",
        ['z'] = "asx"
    };

    private static readonly char[] _vowels = { 'a', 'e', 'i', 'o', 'u' };
    private const string _additionAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789";

    private static (string Prefix, string Label, string Suffix) SplitDomain(string domainName, PublicSuffixList list)
    {
        var clean = domainName.Trim('.');
        var parts = clean.Split('.');
        if (parts.Length == 1)
        {
            return (string.Empty, clean, string.Empty);
        }

        for (int i = 0; i < parts.Length; i++)
        {
            var candidate = string.Join(".", parts.Skip(i));
            if (list.IsPublicSuffix(candidate))
            {
                var labelIndex = i - 1;
                if (labelIndex >= 0)
                {
                    var prefix = string.Join(".", parts.Take(labelIndex));
                    if (prefix.Length > 0)
                    {
                        prefix += ".";
                    }

                    var suffix = "." + string.Join(".", parts.Skip(labelIndex + 1));
                    return (prefix, parts[labelIndex], suffix);
                }
            }
        }

        var idx = clean.IndexOf('.');
        if (idx > 0)
        {
            return (string.Empty, clean.Substring(0, idx), clean.Substring(idx));
        }

        return (string.Empty, clean, string.Empty);
    }

    private static IReadOnlyList<TyposquattingCandidate> BuildCandidates(
        string domainName,
        PublicSuffixList list,
        int threshold,
        IReadOnlyCollection<string> brands,
        IReadOnlyCollection<string> dictionaryWords,
        IReadOnlyCollection<string> alternativeTlds)
    {
        var normalizedSource = NormalizeCandidateDomain(domainName);
        var (prefix, label, suffix) = SplitDomain(normalizedSource, list);
        var candidates = new Dictionary<string, TyposquattingCandidate>(StringComparer.OrdinalIgnoreCase);

        void AddMutation(TyposquattingVariantKind kind, string mutatedLabel, bool bypassThreshold = false)
        {
            if (string.IsNullOrWhiteSpace(mutatedLabel))
            {
                return;
            }

            var candidate = prefix + mutatedLabel + suffix;
            AddCandidate(kind, candidate, bypassThreshold);
        }

        void AddCandidate(TyposquattingVariantKind kind, string candidateDomain, bool bypassThreshold = false)
        {
            if (string.IsNullOrWhiteSpace(candidateDomain))
            {
                return;
            }

            string normalized;
            try
            {
                normalized = NormalizeCandidateDomain(candidateDomain);
            }
            catch (ArgumentException)
            {
                return;
            }

            if (string.Equals(normalized, normalizedSource, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var distance = StringAlgorithms.LevenshteinDistance(normalizedSource, normalized);
            if (!bypassThreshold && distance > threshold)
            {
                return;
            }

            if (!candidates.TryGetValue(normalized, out var existing) || distance < existing.EditDistance)
            {
                candidates[normalized] = new TyposquattingCandidate
                {
                    Domain = normalized,
                    Kind = kind,
                    EditDistance = distance
                };
            }
        }

        for (int i = 0; i < label.Length; i++)
        {
            AddMutation(TyposquattingVariantKind.Omission, label.Remove(i, 1));
        }

        for (int i = 0; i < label.Length; i++)
        {
            AddMutation(TyposquattingVariantKind.Repetition, label.Insert(i, label[i].ToString()));
        }

        for (int i = 0; i < label.Length - 1; i++)
        {
            if (label[i] == label[i + 1])
            {
                continue;
            }

            var chars = label.ToCharArray();
            (chars[i], chars[i + 1]) = (chars[i + 1], chars[i]);
            AddMutation(TyposquattingVariantKind.Transposition, new string(chars));
        }

        for (int i = 1; i < label.Length; i++)
        {
            AddMutation(TyposquattingVariantKind.Hyphenation, label.Insert(i, "-"));
            AddMutation(TyposquattingVariantKind.Subdomain, label.Insert(i, "."));
        }

        for (int i = 0; i < label.Length; i++)
        {
            var current = char.ToLowerInvariant(label[i]);
            if (_keyboardNeighbors.TryGetValue(current, out var neighbors))
            {
                foreach (var neighbor in neighbors.Distinct())
                {
                    AddMutation(TyposquattingVariantKind.Replacement, ReplaceChar(label, i, neighbor));
                    AddMutation(TyposquattingVariantKind.Insertion, label.Insert(i, neighbor.ToString()));
                    AddMutation(TyposquattingVariantKind.Insertion, label.Insert(i + 1, neighbor.ToString()));
                }
            }
        }

        for (int i = 0; i < label.Length; i++)
        {
            var current = char.ToLowerInvariant(label[i]);
            if (Array.IndexOf(_vowels, current) >= 0)
            {
                foreach (var vowel in _vowels)
                {
                    if (vowel == current)
                    {
                        continue;
                    }

                    AddMutation(TyposquattingVariantKind.VowelSwap, ReplaceChar(label, i, vowel));
                }
            }
        }

        for (int i = 0; i < label.Length; i++)
        {
            var current = char.ToLowerInvariant(label[i]);
            if (_homoglyphs.TryGetValue(current, out var homoglyphs))
            {
                foreach (var homoglyph in homoglyphs.Distinct())
                {
                    AddMutation(TyposquattingVariantKind.Homoglyph, ReplaceChar(label, i, homoglyph));
                }
            }

            if (_latinToCyrillic.TryGetValue(current, out var cyrillic))
            {
                AddMutation(TyposquattingVariantKind.Cyrillic, ReplaceChar(label, i, cyrillic));
            }
        }

        for (int i = 0; i < label.Length; i++)
        {
            var current = label[i];
            for (int bit = 0; bit < 8; bit++)
            {
                var flipped = (char)(current ^ (1 << bit));
                if (!IsValidLabelCharacter(flipped))
                {
                    continue;
                }

                AddMutation(TyposquattingVariantKind.Bitsquatting, ReplaceChar(label, i, char.ToLowerInvariant(flipped)));
            }
        }

        foreach (var ch in _additionAlphabet)
        {
            AddMutation(TyposquattingVariantKind.Addition, ch + label);
            AddMutation(TyposquattingVariantKind.Addition, label + ch);
        }

        if (!label.EndsWith("s", StringComparison.OrdinalIgnoreCase))
        {
            AddMutation(TyposquattingVariantKind.Plural, label + "s");
        }

        foreach (var word in dictionaryWords)
        {
            if (string.IsNullOrWhiteSpace(word))
            {
                continue;
            }

            var normalizedWord = NormalizeLabelFragment(word);
            if (normalizedWord.Length == 0)
            {
                continue;
            }

            AddMutation(TyposquattingVariantKind.Dictionary, normalizedWord + label, bypassThreshold: true);
            AddMutation(TyposquattingVariantKind.Dictionary, label + normalizedWord, bypassThreshold: true);
            AddMutation(TyposquattingVariantKind.Dictionary, normalizedWord + "-" + label, bypassThreshold: true);
            AddMutation(TyposquattingVariantKind.Dictionary, label + "-" + normalizedWord, bypassThreshold: true);
        }

        foreach (var brand in brands)
        {
            if (string.IsNullOrWhiteSpace(brand))
            {
                continue;
            }

            var normalizedBrand = NormalizeLabelFragment(brand);
            if (normalizedBrand.Length == 0)
            {
                continue;
            }

            AddMutation(TyposquattingVariantKind.BrandCombination, normalizedBrand + label, bypassThreshold: true);
            AddMutation(TyposquattingVariantKind.BrandCombination, label + normalizedBrand, bypassThreshold: true);
            AddMutation(TyposquattingVariantKind.BrandCombination, normalizedBrand + "-" + label, bypassThreshold: true);
            AddMutation(TyposquattingVariantKind.BrandCombination, label + "-" + normalizedBrand, bypassThreshold: true);
        }

        foreach (var tld in alternativeTlds)
        {
            if (string.IsNullOrWhiteSpace(tld))
            {
                continue;
            }

            var trimmed = tld.Trim().Trim('.').ToLowerInvariant();
            if (trimmed.Length == 0 || string.Equals(trimmed, suffix.TrimStart('.'), StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            AddCandidate(TyposquattingVariantKind.TldSwap, prefix + label + "." + trimmed, bypassThreshold: true);
        }

        return candidates.Values
            .OrderBy(c => c.EditDistance)
            .ThenBy(c => c.Kind)
            .ThenBy(c => c.Domain, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string ReplaceChar(string value, int index, char replacement)
    {
        var chars = value.ToCharArray();
        chars[index] = replacement;
        return new string(chars);
    }

    private static bool IsValidLabelCharacter(char value)
    {
        return (value >= 'a' && value <= 'z') ||
               (value >= 'A' && value <= 'Z') ||
               (value >= '0' && value <= '9') ||
               value == '-';
    }

    private static string NormalizeLabelFragment(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var chars = value
            .Trim()
            .ToLowerInvariant()
            .Where(ch => char.IsLetterOrDigit(ch) || ch == '-')
            .ToArray();

        return new string(chars).Trim('-');
    }

    private static string NormalizeCandidateDomain(string candidate)
    {
        return DomainHelper.ValidateIdn(candidate.Trim().Trim('.')).ToLowerInvariant();
    }
}
