using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace DomainDetective;

/// <summary>
/// Collection of <see cref="BlockListEntry"/> ensuring entries are valid.
/// </summary>
public class BlockListEntryCollection : Collection<BlockListEntry> {
    public BlockListEntryCollection() : base() { }

    public BlockListEntryCollection(IEnumerable<BlockListEntry> items) {
        if (items == null)
            return;
        foreach (var item in items)
            Add(item);
    }

    protected override void InsertItem(int index, BlockListEntry item) {
        ValidateItem(item);
        base.InsertItem(index, item);
    }

    protected override void SetItem(int index, BlockListEntry item) {
        ValidateItem(item);
        base.SetItem(index, item);
    }

    private static void ValidateItem(BlockListEntry item) {
        if (item == null)
            throw new ArgumentNullException(nameof(item));
        if (string.IsNullOrWhiteSpace(item.Name))
            throw new ArgumentException("Name cannot be null or whitespace.", nameof(item));
    }
}