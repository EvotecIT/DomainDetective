using System;

namespace DomainDetective {
    public partial class BimiAnalysis {
        /// <summary>
        /// Resets analysis state to initial values.
        /// </summary>
        internal void ResetState() {
            BimiRecord = null;
            BimiRecordExists = false;
            StartsCorrectly = false;
            Location = null;
            Authority = null;
            LocationUsesHttps = false;
            AuthorityUsesHttps = false;
            DeclinedToPublish = false;
            InvalidLocation = false;
            SvgFetched = false;
            SvgValid = false;
            SvgInvalidReason = null;
            SvgSizeValid = false;
            DimensionsValid = false;
            ViewBoxValid = false;
            SvgAttributesPresent = false;
            ValidVmc = false;
            VmcSignedByKnownRoot = false;
            VmcContainsLogo = false;
            VmcCertificate = null;
            FailureReason = null;
        }

        /// <summary>
        /// Parses a BIMI record header and populates basic fields.
        /// </summary>
        /// <param name="record">The raw BIMI record text.</param>
        /// <param name="logger">Logger for warnings.</param>
        internal void ParseBimiHeader(string record, InternalLogger? logger) {
            if (record == null) {
                throw new ArgumentNullException(nameof(record));
            }

            BimiRecord = record;
            StartsCorrectly = record.StartsWith("v=BIMI1", StringComparison.OrdinalIgnoreCase);

            foreach (var part in record.Split(';')) {
                var kv = part.Split(new[] { '=' }, 2);
                if (kv.Length != 2) {
                    continue;
                }

                var key = kv[0].Trim();
                var value = kv[1].Trim();

                switch (key) {
                    case "l":
                        Location = value;
                        InvalidLocation = !(value.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                            && (value.EndsWith(".svg", StringComparison.OrdinalIgnoreCase)
                                || value.EndsWith(".svgz", StringComparison.OrdinalIgnoreCase)));
                        if (InvalidLocation) {
                            logger?.WriteWarningCode(BimiCodes.InvalidLocation, "Invalid BIMI indicator location {0}", value);
                        }
                        break;
                    case "a":
                        Authority = value;
                        break;
                }
            }

            var location = Location;
            LocationUsesHttps = location == null || location.Length == 0 || location.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            var authority = Authority;
            AuthorityUsesHttps = authority == null || authority.Length == 0 || authority.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
            DeclinedToPublish = (location == null || location.Length == 0) && (authority == null || authority.Length == 0);
        }
    }
}
