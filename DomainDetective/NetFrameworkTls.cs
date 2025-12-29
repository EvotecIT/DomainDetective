using System.Threading;
#if NETFRAMEWORK
using System.Net;
#endif

namespace DomainDetective {
    internal static class NetFrameworkTls {
#if NETFRAMEWORK
        private static int _initialized;
#endif

        internal static void EnsureEnabled() {
#if NETFRAMEWORK
            if (Interlocked.Exchange(ref _initialized, 1) == 1) {
                return;
            }
            try {
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            } catch {
                // Best-effort: leave defaults if the platform disallows changes.
            }
#endif
        }
    }
}
