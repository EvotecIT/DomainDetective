using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Analyzes a raw SMIMEA record.
        /// </summary>
        /// <param name="smimeaRecord">SMIMEA record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSMIMEA(string smimeaRecord, CancellationToken cancellationToken = default) {
            await SmimeaAnalysis.AnalyzeSMIMEARecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = smimeaRecord
                }
            }, _logger);
        }

        /// <summary>
        /// Queries SMIMEA records for an email address.
        /// </summary>
        /// <param name="emailAddress">Email address to query.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySMIMEA(string emailAddress, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(emailAddress)) {
                throw new ArgumentNullException(nameof(emailAddress));
            }

            var name = SMIMEAAnalysis.GetQueryName(emailAddress);
            SmimeaAnalysis = new SMIMEAAnalysis();
            var records = await DnsConfiguration.QueryDNS(name, DnsRecordType.SMIMEA, cancellationToken: cancellationToken);
            if (records.Any()) {
                await SmimeaAnalysis.AnalyzeSMIMEARecords(records, _logger);
            } else {
                _logger.WriteWarningCode(SmimeaCodes.NoRecords, "No SMIMEA records found.");
            }
        }
    }
}
