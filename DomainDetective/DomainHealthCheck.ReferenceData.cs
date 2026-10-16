using System;

namespace DomainDetective;

public partial class DomainHealthCheck {
    // PublicSuffixList exposes queries only; refresh replaces an instance rather than mutating it.
    private static readonly Lazy<PublicSuffixList> _bundledPublicSuffixList = new(() => {
        using var stream = typeof(DomainHealthCheck).Assembly.GetManifestResourceStream("DomainDetective.public_suffix_list.dat");
        return stream == null ? new PublicSuffixList() : PublicSuffixList.Load(stream);
    });
}
