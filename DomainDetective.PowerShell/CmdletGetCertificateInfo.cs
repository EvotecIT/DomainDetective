using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell {
    /// <summary>Returns details about a certificate file.</summary>
    /// <example>
    ///   <summary>Analyze a PEM certificate.</summary>
    ///   <code>Get-CertificateInfo -Path ./cert.pem</code>
    /// </example>
    [Cmdlet(VerbsCommon.Get, "CertificateInfo")]
    public sealed class CmdletGetCertificateInfo : AsyncPSCmdlet {
        /// <param name="Path">Path to a PEM or DER encoded certificate.</param>
        [Parameter(Mandatory = true, Position = 0)]
        [ValidateNotNullOrEmpty]
        public string Path;

        /// <param name="ShowChain">Include certificate chain in the output.</param>
        [Parameter(Mandatory = false)]
        public SwitchParameter ShowChain;

        private CertificateAnalysis _analysis;

        protected override async Task ProcessRecordAsync() {
            _analysis = new CertificateAnalysis();
            await _analysis.AnalyzeCertificate(new X509Certificate2(Path));
            WriteObject(_analysis);
            if (ShowChain && _analysis.Chain.Count > 0) {
                WriteObject(_analysis.Chain, true);
            }
        }
    }
}
