namespace DomainDetective;

internal static class MxCodes {
    public const string Missing = "MX.Missing";
    public const string CnameTarget = "MX.CNAME.Target";
    public const string IpTarget = "MX.IP.Target";
    public const string TargetNonExistent = "MX.Target.NXDOMAIN";
    public const string TargetNoAddressRecords = "MX.Target.NoAddress";
    public const string PrioritiesOutOfOrder = "MX.Priority.OutOfOrder";
    public const string NoBackupServers = "MX.Backup.Missing";
    public const string NullMxPresent = "MX.NullMX.Present";
    public const string LocalhostTarget = "MX.Target.Localhost";
    public const string RrsetInconsistentAcrossNs = "MX.RRSet.InconsistentAcrossNS";
    public const string TargetAddressInconsistentAcrossNs = "MX.Target.Address.InconsistentAcrossNS";
    public const string TtlNonUniform = "MX.TTL.NonUniform";
    public const string TargetTtlNonUniform = "MX.Target.TTL.NonUniform";
}

