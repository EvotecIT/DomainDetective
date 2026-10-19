using System.Runtime.InteropServices;
using Xunit;

namespace DomainDetective.Tests;

/// <summary>Runs an ephemeral TLS server fixture where the TLS provider supports its in-memory private key.</summary>
public sealed class EphemeralTlsFactAttribute : FactAttribute {
    public EphemeralTlsFactAttribute() {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
            Skip = "Windows Schannel cannot authenticate this ephemeral server key; run the fixture on Linux or macOS.";
        }
    }
}
