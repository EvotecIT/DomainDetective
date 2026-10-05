using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class SpfAnalysis {
    private readonly List<string> _flatteningLimitations = new();

    /// <summary>True when the generated policy has no retained include or redirect dependencies.</summary>
    public bool FlatteningComplete => _flatteningLimitations.Count == 0;
    /// <summary>Reasons that dependencies were retained to preserve authorization semantics.</summary>
    public IReadOnlyList<string> FlatteningLimitations => _flatteningLimitations;

    private void RetainFlatteningDependency(string token, string reason, InternalLogger? logger) {
        string message = $"Retained {token}: {reason}.";
        _flatteningLimitations.Add(message);
        _warnings.Add(message);
        logger?.WriteWarningCode("SPF.Flattening.Incomplete", message);
    }

    private async Task<List<string>> FlattenTokens(IEnumerable<string> tokens, HashSet<string> visited,
        InternalLogger? logger, string? evaluationDomain = null) {
        var source = tokens.ToArray();
        var result = new List<string> { "v=spf1" };
        bool reachedAll = false;
        bool hasAll = source.Any(IsAllMechanism);
        foreach (string term in source.Skip(1)) {
            if (TryGetSpfModifier(term, out string modifier, out _)) {
                if (modifier.Equals("redirect", StringComparison.OrdinalIgnoreCase)) {
                    if (hasAll) continue;
                    RetainFlatteningDependency(term, "redirect result and domain context require the original dependency", logger);
                }
                result.Add(term);
                continue;
            }
            if (reachedAll) continue;
            string token = "+-~?".IndexOf(term[0]) >= 0 ? term.Substring(1) : term;
            char qualifier = "+-~?".IndexOf(term[0]) >= 0 ? term[0] : '+';
            if (token.StartsWith("include:", StringComparison.OrdinalIgnoreCase)) {
                string domain = token.Substring(8);
                if (qualifier != '+' || domain.IndexOf('%') >= 0 || !visited.Add(domain)) {
                    RetainFlatteningDependency(term, "qualified, macro-dependent, or cyclic include cannot be safely spliced", logger);
                    result.Add(term);
                    continue;
                }
                try {
                    string? record;
                    if (!TestSpfRecords.TryGetValue(domain, out record)) {
                        var answers = await DnsConfiguration.QueryPolicyDNS(domain, DnsRecordType.TXT);
                        var records = answers.Where(answer => answer.Type == DnsRecordType.TXT)
                            .Select(answer => answer.TxtConcatenatedData).Where(IsSpfPolicyRecord).ToArray();
                        record = records.Length == 1 ? records[0] : null;
                    }
                    if (record == null || !TryValidateSpfSyntax(record, out var child, out _, out _)
                        || !CanInlineSpfInclude(child)) {
                        RetainFlatteningDependency(term, "the child has no unique valid policy or contains non-Pass/context-dependent conditions", logger);
                        result.Add(term);
                        continue;
                    }
                    var flattened = await FlattenTokens(child, visited, logger, domain);
                    foreach (string mechanism in flattened.Skip(1)) {
                        if (TryGetSpfModifier(mechanism, out _, out _)) continue;
                        if (IsAllMechanism(mechanism) && mechanism[0] != '+' && !mechanism.Equals("all", StringComparison.OrdinalIgnoreCase)) break;
                        result.Add(mechanism);
                        if (IsAllMechanism(mechanism)) { reachedAll = true; break; }
                    }
                } catch (OperationCanceledException) {
                    throw;
                } catch (Exception ex) {
                    RetainFlatteningDependency(term, "the dependency lookup failed: " + ex.Message, logger);
                    result.Add(term);
                } finally {
                    visited.Remove(domain);
                }
            } else {
                if (!string.IsNullOrEmpty(evaluationDomain)) {
                    foreach (string name in new[] { "a", "mx", "ptr" }) {
                        if (token.Equals(name, StringComparison.OrdinalIgnoreCase) || token.StartsWith(name + "/", StringComparison.OrdinalIgnoreCase)) {
                            token = name + ":" + evaluationDomain + token.Substring(name.Length);
                            break;
                        }
                    }
                    result.Add((qualifier == '+' ? string.Empty : qualifier.ToString()) + token);
                } else {
                    result.Add(term);
                }
                reachedAll = IsAllMechanism(term);
            }
        }
        return result;
    }

    private static bool CanInlineSpfInclude(string[] terms) {
        foreach (string term in terms.Skip(1)) {
            if (term.IndexOf('%') >= 0) return false;
            if (TryGetSpfModifier(term, out string modifier, out _)) {
                if (modifier.Equals("redirect", StringComparison.OrdinalIgnoreCase) && !terms.Any(IsAllMechanism)) return false;
                continue;
            }
            if (IsAllMechanism(term)) return true;
            if ("-~?".IndexOf(term[0]) >= 0) return false;
        }
        return true;
    }
}
