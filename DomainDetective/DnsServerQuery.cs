namespace DomainDetective {
    /// <summary>
    /// Builder for querying DNS servers by country, location and count.
    /// </summary>
    public sealed class DnsServerQuery {
        /// <summary>Selected country.</summary>
        public CountryId? Country { get; private set; }
        /// <summary>Selected location.</summary>
        public LocationId? Location { get; private set; }
        /// <summary>Number of servers to take.</summary>
    public int? TakeCount { get; private set; }

    /// <summary>Creates a new query instance.</summary>
    public static DnsServerQuery Create() => new();

    /// <summary>Filters by country name.</summary>
    public DnsServerQuery FromCountry(string name) {
        if (!string.IsNullOrWhiteSpace(name) &&
            CountryIdExtensions.TryParse(name.Trim().ToUpperInvariant(), out var id)) {
            Country = id;
        }
        return this;
    }

    /// <summary>Filters by country enum.</summary>
    public DnsServerQuery FromCountry(CountryId id) {
        Country = id;
        return this;
    }

    /// <summary>Filters by location name.</summary>
    public DnsServerQuery FromLocation(string name) {
        if (!string.IsNullOrWhiteSpace(name) &&
            LocationIdExtensions.TryParse(name.Trim().ToUpperInvariant(), out var id)) {
            Location = id;
        }
        return this;
    }

    /// <summary>Filters by location enum.</summary>
    public DnsServerQuery FromLocation(LocationId id) {
        Location = id;
        return this;
    }

    /// <summary>Limits the number of servers returned.</summary>
    public DnsServerQuery Take(int count) {
        TakeCount = count > 0 ? count : null;
        return this;
    }
    }
}
