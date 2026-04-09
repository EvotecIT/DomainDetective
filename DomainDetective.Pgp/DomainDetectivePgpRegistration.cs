using DomainDetective;

namespace DomainDetective.Pgp;

/// <summary>
/// Registers the optional PGP-backed security.txt verifier.
/// </summary>
public static class DomainDetectivePgpRegistration
{
    public static void Register()
    {
        DomainDetectiveOptionalFeatures.RegisterPgpVerifier(DomainDetectivePgpProvider.VerifyClearSignedMessage);
    }
}
