using System;

namespace DomainDetective;

/// <summary>
/// Edge PoP code normalization for WebStaticScanAnalysis.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private sealed class PopInfo
    {
        public string City { get; }
        public string Country { get; }
        public string Region { get; }
        public PopInfo(string city, string country, string region) { City = city; Country = country; Region = region; }
    }

    private static readonly System.Collections.Generic.Dictionary<string, PopInfo> _popMap = new(System.StringComparer.OrdinalIgnoreCase)
    {
        // North America
        ["IAD"] = new PopInfo("Ashburn", "United States", "North America"),
        ["EWR"] = new PopInfo("Newark", "United States", "North America"),
        ["JFK"] = new PopInfo("New York", "United States", "North America"),
        ["BOS"] = new PopInfo("Boston", "United States", "North America"),
        ["PHL"] = new PopInfo("Philadelphia", "United States", "North America"),
        ["ATL"] = new PopInfo("Atlanta", "United States", "North America"),
        ["MIA"] = new PopInfo("Miami", "United States", "North America"),
        ["DFW"] = new PopInfo("Dallas", "United States", "North America"),
        ["IAH"] = new PopInfo("Houston", "United States", "North America"),
        ["DEN"] = new PopInfo("Denver", "United States", "North America"),
        ["PHX"] = new PopInfo("Phoenix", "United States", "North America"),
        ["LAS"] = new PopInfo("Las Vegas", "United States", "North America"),
        ["SEA"] = new PopInfo("Seattle", "United States", "North America"),
        ["SFO"] = new PopInfo("San Francisco", "United States", "North America"),
        ["SJC"] = new PopInfo("San Jose", "United States", "North America"),
        ["LAX"] = new PopInfo("Los Angeles", "United States", "North America"),
        ["ORD"] = new PopInfo("Chicago", "United States", "North America"),
        ["MSP"] = new PopInfo("Minneapolis", "United States", "North America"),
        ["CMH"] = new PopInfo("Columbus", "United States", "North America"),
        ["MCI"] = new PopInfo("Kansas City", "United States", "North America"),
        ["CLT"] = new PopInfo("Charlotte", "United States", "North America"),
        ["RDU"] = new PopInfo("Raleigh", "United States", "North America"),
        ["YYZ"] = new PopInfo("Toronto", "Canada", "North America"),
        ["YUL"] = new PopInfo("Montreal", "Canada", "North America"),
        ["YVR"] = new PopInfo("Vancouver", "Canada", "North America"),
        ["YYC"] = new PopInfo("Calgary", "Canada", "North America"),
        // Europe
        ["LHR"] = new PopInfo("London", "United Kingdom", "Europe"),
        ["LGW"] = new PopInfo("London", "United Kingdom", "Europe"),
        ["MAN"] = new PopInfo("Manchester", "United Kingdom", "Europe"),
        ["AMS"] = new PopInfo("Amsterdam", "Netherlands", "Europe"),
        ["FRA"] = new PopInfo("Frankfurt", "Germany", "Europe"),
        ["BER"] = new PopInfo("Berlin", "Germany", "Europe"),
        ["MUC"] = new PopInfo("Munich", "Germany", "Europe"),
        ["DUS"] = new PopInfo("Düsseldorf", "Germany", "Europe"),
        ["HAM"] = new PopInfo("Hamburg", "Germany", "Europe"),
        ["CDG"] = new PopInfo("Paris", "France", "Europe"),
        ["BRU"] = new PopInfo("Brussels", "Belgium", "Europe"),
        ["PRG"] = new PopInfo("Prague", "Czechia", "Europe"),
        ["WAW"] = new PopInfo("Warsaw", "Poland", "Europe"),
        ["VIE"] = new PopInfo("Vienna", "Austria", "Europe"),
        ["ZRH"] = new PopInfo("Zurich", "Switzerland", "Europe"),
        ["GVA"] = new PopInfo("Geneva", "Switzerland", "Europe"),
        ["CPH"] = new PopInfo("Copenhagen", "Denmark", "Europe"),
        ["ARN"] = new PopInfo("Stockholm", "Sweden", "Europe"),
        ["OSL"] = new PopInfo("Oslo", "Norway", "Europe"),
        ["HEL"] = new PopInfo("Helsinki", "Finland", "Europe"),
        ["DUB"] = new PopInfo("Dublin", "Ireland", "Europe"),
        ["MAD"] = new PopInfo("Madrid", "Spain", "Europe"),
        ["BCN"] = new PopInfo("Barcelona", "Spain", "Europe"),
        ["LIS"] = new PopInfo("Lisbon", "Portugal", "Europe"),
        ["MXP"] = new PopInfo("Milan", "Italy", "Europe"),
        ["FCO"] = new PopInfo("Rome", "Italy", "Europe"),
        ["ATH"] = new PopInfo("Athens", "Greece", "Europe"),
        ["IST"] = new PopInfo("Istanbul", "Turkey", "Europe"),
        ["EDI"] = new PopInfo("Edinburgh", "United Kingdom", "Europe"),
        ["GLA"] = new PopInfo("Glasgow", "United Kingdom", "Europe"),
        // Asia
        ["HKG"] = new PopInfo("Hong Kong", "China (SAR)", "Asia"),
        ["NRT"] = new PopInfo("Tokyo", "Japan", "Asia"),
        ["KIX"] = new PopInfo("Osaka", "Japan", "Asia"),
        ["ICN"] = new PopInfo("Seoul", "South Korea", "Asia"),
        ["SIN"] = new PopInfo("Singapore", "Singapore", "Asia"),
        ["TPE"] = new PopInfo("Taipei", "Taiwan", "Asia"),
        ["BKK"] = new PopInfo("Bangkok", "Thailand", "Asia"),
        ["KUL"] = new PopInfo("Kuala Lumpur", "Malaysia", "Asia"),
        ["CGK"] = new PopInfo("Jakarta", "Indonesia", "Asia"),
        ["MNL"] = new PopInfo("Manila", "Philippines", "Asia"),
        ["DEL"] = new PopInfo("Delhi", "India", "Asia"),
        ["BOM"] = new PopInfo("Mumbai", "India", "Asia"),
        ["HYD"] = new PopInfo("Hyderabad", "India", "Asia"),
        ["MAA"] = new PopInfo("Chennai", "India", "Asia"),
        ["BLR"] = new PopInfo("Bengaluru", "India", "Asia"),
        // Oceania
        ["SYD"] = new PopInfo("Sydney", "Australia", "Oceania"),
        ["MEL"] = new PopInfo("Melbourne", "Australia", "Oceania"),
        ["BNE"] = new PopInfo("Brisbane", "Australia", "Oceania"),
        ["PER"] = new PopInfo("Perth", "Australia", "Oceania"),
        ["AKL"] = new PopInfo("Auckland", "New Zealand", "Oceania"),
        // South America
        ["GRU"] = new PopInfo("São Paulo", "Brazil", "South America"),
        ["EZE"] = new PopInfo("Buenos Aires", "Argentina", "South America"),
        ["SCL"] = new PopInfo("Santiago", "Chile", "South America"),
        ["LIM"] = new PopInfo("Lima", "Peru", "South America"),
        ["BOG"] = new PopInfo("Bogotá", "Colombia", "South America"),
        // Middle East & Africa
        ["DXB"] = new PopInfo("Dubai", "United Arab Emirates", "Middle East"),
        ["DOH"] = new PopInfo("Doha", "Qatar", "Middle East"),
        ["AUH"] = new PopInfo("Abu Dhabi", "United Arab Emirates", "Middle East"),
        ["TLV"] = new PopInfo("Tel Aviv", "Israel", "Middle East"),
        ["JED"] = new PopInfo("Jeddah", "Saudi Arabia", "Middle East"),
        ["RUH"] = new PopInfo("Riyadh", "Saudi Arabia", "Middle East"),
        ["JNB"] = new PopInfo("Johannesburg", "South Africa", "Africa"),
        ["CPT"] = new PopInfo("Cape Town", "South Africa", "Africa"),
        ["CAI"] = new PopInfo("Cairo", "Egypt", "Africa"),
        ["CMN"] = new PopInfo("Casablanca", "Morocco", "Africa")
    };

    private static string? ExtractPopCode(string? pop)
    {
        if (string.IsNullOrWhiteSpace(pop)) return null;
        var s = pop.Trim();
        // CloudFront: e.g., "FRA56-C1" → "FRA"
        var code = new System.Text.StringBuilder(3);
        foreach (var ch in s)
        {
            if (char.IsLetter(ch))
            {
                code.Append(char.ToUpperInvariant(ch));
                if (code.Length >= 3) break;
            }
            else if (code.Length > 0) break;
        }
        if (code.Length == 3) return code.ToString();
        if (s.Length >= 3)
        {
            var last3 = s.Substring(s.Length - 3).ToUpperInvariant();
            if (char.IsLetter(last3[0]) && char.IsLetter(last3[1]) && char.IsLetter(last3[2])) return last3;
        }
        return null;
    }

    private static void NormalizeEdgePopFields(StaticHost host)
    {
        try
        {
            if (host == null) return;
            if (!string.IsNullOrWhiteSpace(host.EdgePopCity) && !string.IsNullOrWhiteSpace(host.EdgePopCountry) && !string.IsNullOrWhiteSpace(host.EdgePopRegion)) return;
            var code = ExtractPopCode(host.EdgePop);
            if (code == null) return;
            if (_popMap.TryGetValue(code, out var info))
            {
                host.EdgePopCity ??= info.City;
                host.EdgePopCountry ??= info.Country;
                host.EdgePopRegion ??= info.Region;
            }
        }
        catch { }
    }
}

