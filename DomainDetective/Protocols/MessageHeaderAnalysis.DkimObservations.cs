using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public partial class MessageHeaderAnalysis {
    private static string NormalizeSelectorIdentity(string? selector) {
        if (string.IsNullOrWhiteSpace(selector)) return string.Empty;
        try { return DkimDnsName.Selector(selector!); }
        catch (ArgumentException) { return string.Empty; }
    }

    private static HashSet<MessageAuthenticationMethod> ConflictingDkimObservations(IEnumerable<MessageAuthenticationMethod> methods) {
        var conflicts = new HashSet<MessageAuthenticationMethod>();
        foreach (var domain in methods.GroupBy(method => NormalizeDomainIdentity(GetIdentity(method, "header.d")), StringComparer.Ordinal)) {
            var observations = domain.Select(method => (Method: method, Selector: NormalizeSelectorIdentity(GetIdentity(method, "header.s")),
                Prefix: GetIdentity(method, "header.b"))).ToArray();
            var index = new DkimPrefixNode();
            foreach (var observation in observations) index.Add(observation.Prefix, observation.Selector, observation.Method.Result);
            foreach (var observation in observations) {
                if (index.Conflicts(observation.Prefix, observation.Selector, observation.Method.Result)) conflicts.Add(observation.Method);
            }
        }
        return conflicts;
    }

    // Prefix overlap and missing discriminators are queried in time proportional
    // to the supplied header.b text, without comparing every observation pair.
    private sealed class DkimPrefixNode {
        private readonly Dictionary<char, DkimPrefixNode> _children = new();
        private readonly DkimObservedResults _terminal = new();
        private readonly DkimObservedResults _subtree = new();

        internal void Add(string prefix, string selector, string result) {
            var node = this;
            node._subtree.Add(selector, result);
            foreach (char character in prefix) {
                if (!node._children.TryGetValue(character, out var next)) {
                    next = new DkimPrefixNode();
                    node._children.Add(character, next);
                }
                node = next;
                node._subtree.Add(selector, result);
            }
            node._terminal.Add(selector, result);
        }

        internal bool Conflicts(string prefix, string selector, string result) {
            var node = this;
            if (node._terminal.Conflicts(selector, result)) return true;
            foreach (char character in prefix) {
                if (!node._children.TryGetValue(character, out var next)) return false;
                node = next;
                if (node._terminal.Conflicts(selector, result)) return true;
            }
            return node._subtree.Conflicts(selector, result);
        }
    }

    private sealed class DkimObservedResults {
        private readonly Dictionary<string, string?> _selectors = new(StringComparer.Ordinal);
        private string? _first;
        private bool _mixed;

        internal void Add(string selector, string result) {
            if (_first == null) _first = result;
            else if (!string.Equals(_first, result, StringComparison.OrdinalIgnoreCase)) _mixed = true;
            if (!_selectors.TryGetValue(selector, out var prior)) _selectors.Add(selector, result);
            else if (!string.Equals(prior, result, StringComparison.OrdinalIgnoreCase)) _selectors[selector] = null;
        }

        internal bool Conflicts(string selector, string result) => selector.Length == 0
            ? _first != null && (_mixed || !string.Equals(_first, result, StringComparison.OrdinalIgnoreCase))
            : Differs(selector, result) || Differs(string.Empty, result);

        private bool Differs(string selector, string result) => _selectors.TryGetValue(selector, out var prior)
            && (prior == null || !string.Equals(prior, result, StringComparison.OrdinalIgnoreCase));
    }
}
