using DnsClientX;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Helpers;

internal static class DnsAnswerTtlHelper {
    /// <summary>
    /// Returns the minimum positive TTL (seconds) from a DNS answer set.
    /// </summary>
    /// <remarks>
    /// <para>CNAME answers are ignored since they represent aliasing rather than the RRSet being evaluated.</para>
    /// <para>When <paramref name="expectedType"/> is provided, only answers of that type are considered.</para>
    /// <para>Returns null when no positive TTLs are present.</para>
    /// </remarks>
    internal static int? MinPositiveTtl(IEnumerable<DnsAnswer>? answers, DnsRecordType? expectedType = null) {
        if (answers == null) {
            return null;
        }

        int min = int.MaxValue;
        bool any = false;

        var validAnswers = answers
            .Where(answer => answer.Type != DnsRecordType.CNAME)
            .Where(answer => !expectedType.HasValue || answer.Type == expectedType.Value)
            .Where(answer => answer.TTL > 0);

        foreach (var answer in validAnswers) {
            var ttl = answer.TTL;

            any = true;
            if (ttl < min) {
                min = ttl;
            }
        }

        return any ? min : null;
    }
}
