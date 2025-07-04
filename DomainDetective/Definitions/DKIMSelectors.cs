using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Definitions {
    /// <summary>
    /// Provides common DKIM selectors used by popular mail providers.
    /// </summary>
    internal static class DKIMSelectors {
        internal static readonly string[] Google = new[] { "google" };

        internal static readonly string[] Microsoft = new[] { "selector1", "selector2" };

        internal static readonly string[] Everlytic = new[] { "everlytickey1", "everlytickey2", "eversrv" };

        internal static readonly string[] MailChimp = new[] { "k1" };

        internal static readonly string[] GlobalMicro = new[] { "mxvault" };

        internal static readonly string[] Hetzner = new[] { "dkim" };

        internal static readonly string[] SendGrid = new[] { "s1", "s2" };

        internal static readonly string[] CPanel = new[] { "default", "mail" };

        internal static readonly string[] Fastmail = new[] { "fm1", "fm2", "fm3" };

        internal static readonly string[] AmazonSes = new[] { "amazonses" };

        private static readonly string[] Dmarcian = new[] {
            "selector1",
            "selector2",
            "selector3",
            "selector4",
            "k1",
            "k2",
            "mail",
            "mandrill",
            "mx",
            "s1024",
            "s2048",
            "s1",
            "s2",
            "mx1",
            "mx2",
            "mailchannels",
            "default",
            "google",
            "mta",
            "smtp",
            "dkim",
            "spf",
            "mail1",
            "mail2",
            "api",
            "key1",
            "key2",
            "selector2019",
            "selector2020",
            "selector2021"
        };

        /// <summary>
        /// Returns a deduplicated list of known DKIM selectors.
        /// </summary>
        internal static IEnumerable<string> GuessSelectors() {
            return Google
                .Concat(Microsoft)
                .Concat(Everlytic)
                .Concat(MailChimp)
                .Concat(GlobalMicro)
                .Concat(Hetzner)
                .Concat(SendGrid)
                .Concat(CPanel)
                .Concat(Fastmail)
                .Concat(AmazonSes)
                .Concat(Dmarcian)
                .Distinct();
        }
    }
}