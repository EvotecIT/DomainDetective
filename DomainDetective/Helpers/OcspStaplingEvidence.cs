using System;

namespace DomainDetective.Helpers;

/// <summary>Interprets explicit stapling evidence from OpenSSL without treating an incomplete probe as a negative result.</summary>
internal static class OcspStaplingEvidence {
    internal static bool? Parse(string output, string error) {
        var text = output + "\n" + error;
        if (string.IsNullOrWhiteSpace(text)) { return null; }
        bool present = text.IndexOf("OCSP Response Status:", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf("OCSP Response Data:", StringComparison.OrdinalIgnoreCase) >= 0;
        bool missing = text.IndexOf("OCSP response: no response sent", StringComparison.OrdinalIgnoreCase) >= 0;
        if (missing) { return false; }
        return present ? true : (bool?)null;
    }
}
