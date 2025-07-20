using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace DomainDetective;

/// <summary>
/// Collection of <see cref="DnsblEntry"/> ensuring entries are valid.
/// </summary>
public class DnsblEntryCollection : Collection<DnsblEntry> {
    public DnsblEntryCollection() : base() { }

    public DnsblEntryCollection(IEnumerable<DnsblEntry> items) {
        if (items == null)
            return;
        foreach (var item in items)
            Add(item);
    }

    protected override void InsertItem(int index, DnsblEntry item) {
        ValidateItem(item);
        base.InsertItem(index, item);
    }

    protected override void SetItem(int index, DnsblEntry item) {
        ValidateItem(item);
        base.SetItem(index, item);
    }

    private static void ValidateItem(DnsblEntry item) {
        if (item == null)
            throw new ArgumentNullException(nameof(item));
        if (string.IsNullOrWhiteSpace(item.Domain))
            throw new ArgumentException("Domain cannot be null or whitespace.", nameof(item));
    }
}