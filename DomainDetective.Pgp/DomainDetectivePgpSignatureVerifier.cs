using System;
using PgpCore;
using PgpCore.Models;

namespace DomainDetective.Pgp;

internal static class DomainDetectivePgpProvider
{
    public static (bool IsVerified, string ClearText) VerifyClearSignedMessage(string signedText, string publicKey)
    {
        if (signedText == null)
        {
            throw new ArgumentNullException(nameof(signedText));
        }

        if (string.IsNullOrWhiteSpace(signedText))
        {
            throw new ArgumentException("Signed text must not be empty.", nameof(signedText));
        }

        if (publicKey == null)
        {
            throw new ArgumentNullException(nameof(publicKey));
        }

        if (string.IsNullOrWhiteSpace(publicKey))
        {
            throw new ArgumentException("Public key must not be empty.", nameof(publicKey));
        }

        var keys = new EncryptionKeys(publicKey);
        using var pgp = new PGP(keys);
        VerificationResult result = pgp.VerifyAndReadClearArmoredString(signedText);

        return (result.IsVerified, result.ClearText ?? string.Empty);
    }
}
