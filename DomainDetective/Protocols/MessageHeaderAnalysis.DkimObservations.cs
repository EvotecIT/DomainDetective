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

    // Compressed edges retain views into supplied strings. Both work and retained
    // storage follow the input size; long prefixes do not allocate one node per byte.
    private sealed class DkimPrefixNode {
        private readonly string _edge;
        private int _offset;
        private int _length;
        private readonly Dictionary<char, DkimPrefixNode> _children = new();
        private readonly DkimObservedResults _terminal = new();
        private readonly DkimObservedResults _subtree;

        internal DkimPrefixNode(string edge = "", int offset = 0, int length = 0, DkimObservedResults? subtree = null) {
            _edge = edge; _offset = offset; _length = length;
            _subtree = subtree ?? new DkimObservedResults();
        }

        internal void Add(string prefix, string selector, string result) {
            var node = this;
            node._subtree.Add(selector, result);
            int position = 0;
            while (position < prefix.Length) {
                char character = prefix[position];
                if (!node._children.TryGetValue(character, out var child)) {
                    child = new DkimPrefixNode(prefix, position, prefix.Length - position);
                    node._children.Add(character, child);
                    node = child;
                    node._subtree.Add(selector, result);
                    break;
                }
                int common = 0;
                while (common < child._length && position + common < prefix.Length
                    && prefix[position + common] == child._edge[child._offset + common]) common++;
                if (common < child._length) {
                    var split = new DkimPrefixNode(child._edge, child._offset, common, child._subtree.Copy());
                    child._offset += common;
                    child._length -= common;
                    split._children.Add(child._edge[child._offset], child);
                    node._children[character] = split;
                    node = split;
                } else {
                    node = child;
                }
                position += common;
                node._subtree.Add(selector, result);
            }
            node._terminal.Add(selector, result);
        }

        internal bool Conflicts(string prefix, string selector, string result) {
            var node = this;
            if (node._terminal.Conflicts(selector, result)) return true;
            int position = 0;
            while (position < prefix.Length) {
                if (!node._children.TryGetValue(prefix[position], out var child)) return false;
                int common = 0;
                while (common < child._length && position + common < prefix.Length
                    && prefix[position + common] == child._edge[child._offset + common]) common++;
                if (position + common == prefix.Length) return child._subtree.Conflicts(selector, result);
                if (common < child._length) return false;
                position += common;
                node = child;
                if (node._terminal.Conflicts(selector, result)) return true;
            }
            return node._subtree.Conflicts(selector, result);
        }
    }

    private sealed class DkimObservedResults {
        private readonly Dictionary<string, string?> _selectors = new(StringComparer.Ordinal);
        private string? _first;
        private bool _mixed;

        internal DkimObservedResults Copy() {
            var copy = new DkimObservedResults { _first = _first, _mixed = _mixed };
            foreach (var pair in _selectors) copy._selectors.Add(pair.Key, pair.Value);
            return copy;
        }

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
