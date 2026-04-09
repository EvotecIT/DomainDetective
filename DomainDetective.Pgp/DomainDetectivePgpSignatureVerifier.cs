using System;
using PgpCore;
using PgpCore.Models;

namespace DomainDetective.Pgp;

internal static class DomainDetectivePgpProvider
{
    public static (bool IsVerified, string ClearText) VerifyClearSignedMessage(string signedText, string publicKey)
    {
        var keys = new EncryptionKeys(publicKey);
        using var pgp = new PGP(keys);
        VerificationResult result = pgp.VerifyAndReadClearArmoredString(signedText);

        return (result.IsVerified, result.ClearText ?? string.Empty);
    }
}
