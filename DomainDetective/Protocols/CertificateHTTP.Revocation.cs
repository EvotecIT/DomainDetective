using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace DomainDetective {
    public partial class CertificateAnalysis {
        private async Task QueryRevocationEndpoints(CancellationToken cancellationToken) {
            if (SkipRevocation) {
                return;
            }
            OcspUrls.Clear();
            CrlUrls.Clear();
            OcspRevoked = null;
            CrlRevoked = null;
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (Timeout > TimeSpan.Zero && Timeout != System.Threading.Timeout.InfiniteTimeSpan) deadline.CancelAfter(Timeout);
            try {
                var certificate = Certificate;
                if (certificate == null) {
                    return;
                }
                var parser = new X509CertificateParser();
                var bcCert = parser.ReadCertificate(certificate.RawData);

                var aiaExt = bcCert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
                if (aiaExt != null) {
                    var seq = (Asn1Sequence)Asn1Object.FromByteArray(aiaExt.GetOctets());
                    foreach (var obj in seq) {
                        var ad = AccessDescription.GetInstance(obj);
                        if (ad.AccessMethod.Equals(new DerObjectIdentifier("1.3.6.1.5.5.7.48.1"))) {
                            var name = GeneralName.GetInstance(ad.AccessLocation.ToAsn1Object());
                            if (name.TagNo == GeneralName.UniformResourceIdentifier) {
                                var uri = DerIA5String.GetInstance(name.Name).GetString();
                                OcspUrls.Add(uri);
                            }
                        }
                    }
                }

                var crlExt = bcCert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
                if (crlExt != null) {
                    var cdp = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(crlExt.GetOctets()));
                    foreach (var dp in cdp.GetDistributionPoints()) {
                        var names = dp.DistributionPointName?.Name as GeneralNames;
                        if (names == null) {
                            continue;
                        }
                        foreach (var gn in names.GetNames()) {
                            if (gn.TagNo == GeneralName.UniformResourceIdentifier) {
                                var uri = DerIA5String.GetInstance(gn.Name).GetString();
                                CrlUrls.Add(uri);
                            }
                        }
                    }
                }

                if (OcspUrls.Count > 0 && Chain.Count > 1) {
                    var issuer = FindRevocationIssuer(bcCert);
                    if (issuer == null) return;
                    try {
                        var id = new CertificateID(CertificateID.DigestSha1, issuer, bcCert.SerialNumber);
                        var gen = new OcspReqGenerator();
                        gen.AddRequest(id);
                        var req = gen.Generate();
                        var client = SharedHttpClient.Instance;
                        using var content = new ByteArrayContent(req.GetEncoded());
                        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ocsp-request");
                        using var request = new HttpRequestMessage(HttpMethod.Post, OcspUrls[0]) { Content = content };
                        using var resp = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
                        if (resp.IsSuccessStatusCode) {
                            var bytes = await BoundedHttpContentReader.ReadAsync(resp.Content, 1024 * 1024, deadline.Token).ConfigureAwait(false);
                            OcspRevoked = ParseOcspResponse(bytes, bcCert, issuer, DateTime.UtcNow);
                        }
                    } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                        throw;
                    } catch {
                        // An unavailable or oversized OCSP response does not discard independent CRL evidence.
                    }
                }

                if (CrlUrls.Count > 0) {
                    var client = SharedHttpClient.Instance;
                    using var request = new HttpRequestMessage(HttpMethod.Get, CrlUrls[0]);
                    using var resp = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
                    if (resp.IsSuccessStatusCode) {
                        var bytes = await BoundedHttpContentReader.ReadAsync(resp.Content, 16 * 1024 * 1024, deadline.Token).ConfigureAwait(false);
                        var issuer = FindRevocationIssuer(bcCert);
                        if (issuer != null) CrlRevoked = CertificateRevocationEvidence.CrlStatus(bytes, bcCert, issuer, DateTime.UtcNow);
                    }
                }
            } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                throw;
            } catch {
                // Inconclusive evidence never produces a revocation verdict.
            }
        }

        private Org.BouncyCastle.X509.X509Certificate? FindRevocationIssuer(Org.BouncyCastle.X509.X509Certificate leaf) {
            var parser = new X509CertificateParser();
            foreach (var certificate in Chain) {
                try {
                    var issuer = parser.ReadCertificate(certificate.RawData);
                    if (!leaf.IssuerDN.Equivalent(issuer.SubjectDN)) continue;
                    leaf.Verify(issuer.GetPublicKey());
                    return issuer;
                } catch (Exception) { }
            }
            return null;
        }

        internal static bool? ParseOcspResponse(byte[] response, Org.BouncyCastle.X509.X509Certificate certificate,
            Org.BouncyCastle.X509.X509Certificate issuer, DateTime nowUtc) => CertificateRevocationEvidence.OcspStatus(response, certificate, issuer, nowUtc);
    }
}
