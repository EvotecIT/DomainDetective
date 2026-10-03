using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>One DKIM key record's policy; cryptographic key decoding remains in the existing owners.</summary>
internal sealed class DkimKeyRecord {
    internal Dictionary<string, string> Tags { get; private set; } = new(StringComparer.Ordinal);
    internal bool SyntaxValid { get; private set; }
    internal bool DuplicateTags { get; private set; }
    internal bool VersionPresent => Tags.ContainsKey("v");
    internal bool VersionValid { get; private set; }
    internal string KeyType => Tags.TryGetValue("k", out var value) ? value : "rsa";
    internal string PublicKey => Tags.TryGetValue("p", out var value) ? DkimTagList.RemoveFws(value) : string.Empty;
    internal bool AllowsEmail => !Tags.TryGetValue("s", out var service) || List(service).Any(value => value == "*" || value == "email");
    internal bool StrictIdentity => Tags.TryGetValue("t", out var flags) && List(flags).Contains("s");
    internal bool Testing => Tags.TryGetValue("t", out var flags) && List(flags).Contains("y");
    internal string[] UnknownFlags => Tags.TryGetValue("t", out var flags) ? List(flags).Where(value => value != "s" && value != "y").ToArray() : Array.Empty<string>();

    internal static DkimKeyRecord Parse(string record) {
        var result = new DkimKeyRecord();
        result.SyntaxValid = DkimTagList.TryParse(record, out var tags, out var duplicate);
        result.Tags = tags;
        result.DuplicateTags = duplicate;
        result.VersionValid = !result.VersionPresent || record.Split(';')[0].Split('=')[0].Trim() == "v" && tags["v"] == "DKIM1";
        const string word = @"[A-Za-z](?:[A-Za-z0-9-]*[A-Za-z0-9])?";
        if (tags.TryGetValue("k", out var keyType) && !Regex.IsMatch(keyType, "^" + word + "$")) result.SyntaxValid = false;
        foreach (string name in new[] { "h", "s", "t" }) {
            if (tags.TryGetValue(name, out var value) && List(value).Any(item => !Regex.IsMatch(item, name == "s" ? "^(?:\\*|" + word + ")$" : "^" + word + "$"))) result.SyntaxValid = false;
        }
        return result;
    }

    internal void ValidateUse(string domain, string? algorithm, string? identity) {
        if (!SyntaxValid) throw new DkimKeyPolicyException(DuplicateTags ? "DKIM key record repeats a tag." : "DKIM key tag syntax is invalid.");
        if (!VersionValid) throw new DkimKeyPolicyException("DKIM key version must be DKIM1 and its version tag must be first.");
        if (!Tags.ContainsKey("p")) throw new DkimKeyPolicyException("DKIM key record has no p tag.");
        if (PublicKey.Length == 0) throw new DkimKeyPolicyException("DKIM public key is revoked.");
        if (!AllowsEmail) throw new DkimKeyPolicyException("DKIM key record does not permit the email service.");
        string hash = algorithm?.EndsWith("-sha1", StringComparison.Ordinal) == true ? "sha1" : "sha256";
        if (Tags.TryGetValue("h", out var allowed) && !List(allowed).Contains(hash)) throw new DkimKeyPolicyException("DKIM key record does not permit " + hash + ".");
        if (algorithm != null && !algorithm.StartsWith(KeyType + "-", StringComparison.Ordinal)) throw new DkimKeyPolicyException("DKIM signature algorithm does not match its key type.");
        if (StrictIdentity && identity != null) {
            int at = identity.LastIndexOf('@');
            if (at < 0 || !string.Equals(Helpers.DomainHelper.ValidateIdn(identity.Substring(at + 1)),
                Helpers.DomainHelper.ValidateIdn(domain), StringComparison.OrdinalIgnoreCase)) {
                throw new DkimKeyPolicyException("DKIM key t=s requires the identity domain to equal the signing domain.");
            }
        }
    }

    private static string[] List(string value) => value.Split(':').Select(item => item.Trim(' ', '\t', '\r', '\n')).ToArray();
}

/// <summary>A permanent key-policy failure, distinct from unavailable DNS or key evidence.</summary>
internal sealed class DkimKeyPolicyException : FormatException {
    internal DkimKeyPolicyException(string message) : base(message) { }
}
