using DnsClientX;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Analyzes a raw contact TXT record.
        /// </summary>
        /// <param name="contactRecord">Contact record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckContactInfo(string contactRecord, CancellationToken cancellationToken = default) {
            await ContactInfoAnalysis.AnalyzeContactRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = contactRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }

        /// <summary>
        /// Queries contact TXT records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyContactInfo(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ContactInfoAnalysis = new ContactInfoAnalysis { Subject = domainName };
            var contact = await DnsConfiguration.QueryDNS("contact." + domainName, DnsRecordType.TXT, cancellationToken: cancellationToken);
            await ContactInfoAnalysis.AnalyzeContactRecords(contact, _logger);
        }
    }
}
