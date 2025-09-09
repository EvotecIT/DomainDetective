using System;

namespace DomainDetective.Reports;

/// <summary>
/// Shared ordering options for multi-format composition reports.
/// </summary>
public sealed class OrderingOptions
{
    public DomainOrder DomainOrder { get; set; } = DomainOrder.Alphabetical;
    public SectionOrderMode SectionOrderMode { get; set; } = SectionOrderMode.Canonical;
    public string[]? SectionOrder { get; set; }
}

/// <summary>
/// Controls ordering of domains in composed reports.
/// </summary>
public enum DomainOrder { Alphabetical, Input }

/// <summary>
/// Controls ordering of sections within each domain.
/// </summary>
public enum SectionOrderMode { Canonical, Input, Custom }

