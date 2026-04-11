using System;
using PgpCore;
using PgpCore.Models;

namespace DomainDetective.Pgp;

internal static class DomainDetectivePgpProvider
{
    public static (bool IsVerified, string ClearText) VerifyClearSignedMessage(string signedText, string publicKey)
    {
        if (string.IsNullOrWhiteSpace(signedText))
        {
            throw new ArgumentNullException(nameof(signedText));
        }

        if (string.IsNullOrWhiteSpace(publicKey))
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        var keys = new EncryptionKeys(publicKey);
        using var pgp = new PGP(keys);
        VerificationResult result = pgp.VerifyAndReadClearArmoredString(signedText);

        return (result.IsVerified, result.ClearText ?? string.Empty);
    }
}
