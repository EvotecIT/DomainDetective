using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DomainDetective;

public partial class DkimAnalysis {
    private static bool IsValidKeyRecord(DkimRecordAnalysis analysis) {
        return analysis.DkimRecordExists &&
               !analysis.MultipleRecords &&
               analysis.VersionValid &&
               analysis.PublicKeyExists &&
               analysis.ValidPublicKey &&
               analysis.ValidKeyType &&
               analysis.ValidKeyLength &&
               analysis.ValidFlags;
    }

    private static void ValidatePublicKey(string selector, DkimRecordAnalysis analysis, InternalLogger? logger) {
        analysis.ValidPublicKey = false;
        analysis.ValidRsaKeyLength = false;
        analysis.ValidKeyLength = false;
        analysis.KeyLength = 0;
        analysis.WeakKey = false;

        if (!analysis.PublicKeyExists || !analysis.ValidKeyType) {
            return;
        }

        byte[] keyBytes;
        try {
            var base64 = new string(analysis.PublicKey.Where(c => !char.IsWhiteSpace(c)).ToArray());
            var padding = base64.Length % 4;
            if (padding != 0) {
                base64 += new string('=', 4 - padding);
            }
            keyBytes = Convert.FromBase64String(base64);
        } catch (FormatException) {
            logger?.WriteErrorCode(DkimCodes.KeyInvalid, "DKIM selector {0} contains invalid base64 public key data.", selector);
            return;
        }

        using (var sha256 = SHA256.Create()) {
            analysis.KeyFingerprint = BitConverter.ToString(sha256.ComputeHash(keyBytes)).Replace("-", string.Empty);
        }

        if (string.Equals(analysis.KeyType, "ed25519", StringComparison.OrdinalIgnoreCase)) {
            analysis.KeyLength = keyBytes.Length * 8;
            analysis.ValidKeyLength = keyBytes.Length == 32;
            analysis.ValidPublicKey = analysis.ValidKeyLength;
            if (!analysis.ValidPublicKey) {
                logger?.WriteErrorCode(DkimCodes.KeyInvalid, "DKIM selector {0} must publish exactly 32 octets for an Ed25519 public key.", selector);
            }
            return;
        }

        try {
            var parsed = PublicKeyFactory.CreateKey(keyBytes);
            if (parsed is not RsaKeyParameters rsaKey || rsaKey.IsPrivate) {
                logger?.WriteErrorCode(DkimCodes.KeyInvalid, "DKIM selector {0} does not contain an RSA public key.", selector);
                return;
            }

            analysis.KeyLength = rsaKey.Modulus.BitLength;
            analysis.ValidRsaKeyLength = analysis.KeyLength >= MinimumRsaKeyBits;
            analysis.ValidKeyLength = analysis.ValidRsaKeyLength;
            analysis.ValidPublicKey = analysis.ValidRsaKeyLength;
            analysis.WeakKey = analysis.ValidPublicKey && analysis.KeyLength < 2048;

            if (!analysis.ValidRsaKeyLength) {
                logger?.WriteErrorCode(DkimCodes.KeyTooShort, "DKIM key length {0} bits is below the minimum of {1} bits.", analysis.KeyLength, MinimumRsaKeyBits);
            } else if (analysis.WeakKey) {
                logger?.WriteWarningCode(DkimCodes.KeyWeak, "DKIM key length {0} bits is weak; use at least 2048 bits.", analysis.KeyLength);
            }
        } catch (Exception ex) when (ex is ArgumentException || ex is InvalidCastException || ex is InvalidKeyException) {
            logger?.WriteErrorCode(DkimCodes.KeyInvalid, "DKIM selector {0} contains malformed RSA public key data.", selector);
        }
    }
}
