using System.Security.Cryptography;

namespace DomainDetective.Helpers;

internal static class DnsQueryIdGenerator {
    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

    internal static ushort NextUShort() {
        var bytes = new byte[2];
        Rng.GetBytes(bytes);
        return (ushort)((bytes[0] << 8) | bytes[1]);
    }
}
