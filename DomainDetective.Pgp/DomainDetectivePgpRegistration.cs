using DomainDetective;

namespace DomainDetective.Pgp;

/// <summary>
/// Registers the optional PGP-backed security.txt verifier.
/// </summary>
public static class DomainDetectivePgpRegistration
{
    /// <summary>
    /// Registers the DomainDetective.Pgp verifier, replacing any PGP verifier already registered.
    /// </summary>
    public static void Register()
    {
        DomainDetectiveOptionalFeatures.RegisterPgpVerifier(DomainDetectivePgpProvider.VerifyClearSignedMessage);
    }
}
