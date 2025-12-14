using DnsClientX;
using System.Collections.Generic;

namespace DomainDetective.Helpers;

internal static class DnsAnswerTtlHelper {
    internal static int? MinPositiveTtl(IEnumerable<DnsAnswer>? answers, DnsRecordType? expectedType = null) {
        if (answers == null) return null;

        int min = int.MaxValue;
        bool any = false;
        foreach (var answer in answers) {
            if (answer.Type == DnsRecordType.CNAME) continue;
            if (expectedType.HasValue && answer.Type != expectedType.Value) continue;

            var ttl = answer.TTL;
            if (ttl <= 0) continue;

            any = true;
            if (ttl < min) min = ttl;
        }

        return any ? min : null;
    }
}
