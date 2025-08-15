using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Returns details about a certificate file.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <example>
    ///   <summary>Analyze a PEM certificate.</summary>
    ///   <code>Get-DDCertificateInfo -Path ./cert.pem</code>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "DDCertificateInfo")]
    [Alias("Get-CertificateInfo")]
    public sealed class CmdletGetCertificateInfo : AsyncPSCmdlet {
        /// <para>Path to a PEM or DER encoded certificate.</para>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Path;

        /// <para>Include certificate chain in the output.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowChain;

        /// <para>Do not check certificate revocation status.</para>
        [Parameter(Mandatory = false)]
        public SwitchParameter SkipRevocation;

        private CertificateAnalysis _analysis;

        /// <summary>
        /// Parses the certificate file and writes the analysis to the pipeline.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override async Task ProcessRecordAsync() {
            _analysis = new CertificateAnalysis { SkipRevocation = SkipRevocation };
            await _analysis.AnalyzeCertificate(new X509Certificate2(Path));
            WriteObject(_analysis);
            if (ShowChain && _analysis.Chain.Count > 0) {
                WriteObject(_analysis.Chain, true);
            }
        }
    }
}
