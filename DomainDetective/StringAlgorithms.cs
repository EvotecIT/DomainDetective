using System;
using System.Collections.Generic;

namespace DomainDetective {
    internal static class StringAlgorithms {
        private static readonly Dictionary<char, char[]> _confusables = new() {
            ['a'] = new[] { '\u0430', '\uFF41' },
            ['e'] = new[] { '\u0435', '\uFF45' },
            ['i'] = new[] { '\u0456', '\uFF49' },
            ['o'] = new[] { '\u043E', '\uFF4F' },
            ['c'] = new[] { '\u0441', '\uFF43' },
            ['p'] = new[] { '\u0440', '\uFF50' },
            ['x'] = new[] { '\u0445', '\uFF58' },
            ['y'] = new[] { '\u0443', '\uFF59' },
            ['b'] = new[] { '\u0432', '\uFF42' }
        };

        public static int LevenshteinDistance(string source, string target)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            if (target == null) throw new ArgumentNullException(nameof(target));
            var n = source.Length;
            var m = target.Length;
            var d = new int[n + 1, m + 1];
            for (var i = 0; i <= n; i++) d[i, 0] = i;
            for (var j = 0; j <= m; j++) d[0, j] = j;
            for (var i = 1; i <= n; i++) {
                for (var j = 1; j <= m; j++) {
                    var cost = source[i - 1] == target[j - 1] ? 0 : 1;
                    d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                }
            }
            return d[n, m];
        }

        public static bool ContainsHomoglyphs(string input)
        {
            if (string.IsNullOrEmpty(input))
            {
                return false;
            }

            foreach (var ch in input)
            {
                foreach (var entry in _confusables)
                {
                    if (Array.IndexOf(entry.Value, ch) >= 0)
                    {
                        return true;
                    }
                }
            }

            return false;
        }
    }
}
