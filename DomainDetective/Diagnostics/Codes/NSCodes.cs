namespace DomainDetective;

internal static class NSCodes {
    public const string Missing = "NS.Missing";
    public const string Duplicate = "NS.Duplicate";
    public const string TooFewRecords = "NS.TooFew";
    public const string CnameTarget = "NS.CNAME.Target";
    public const string MissingAddressRecords = "NS.Address.Missing";
    public const string LowDiversity = "NS.Diversity.Low";
    // Positive signals
    public const string HighDiversity = "NS.Diversity.High";
    public const string DelegationMismatch = "NS.Delegation.Mismatch";
    public const string GlueIncomplete = "NS.Glue.Incomplete";
    public const string GlueInconsistent = "NS.Glue.Inconsistent";
    public const string RecursionOnAuthoritative = "NS.Recursion.Enabled";
}

