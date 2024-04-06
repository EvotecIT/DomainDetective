using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective {
    public class SecurityTXTAnalysis {
        public string Domain { get; set; }
        public bool RecordPresent { get; set; }
        public bool RecordValid { get; set; }
        public bool PGPSigned { get; set; }
        public bool FallbackUsed { get; set; }
        public string Url { get; set; }
        // Fields that can appear multiple times as List<string>
        public List<string> ContactEmail { get; set; } = new List<string>();
        public List<string> ContactWebsite { get; set; } = new List<string>();
        public List<string> Acknowledgments { get; set; } = new List<string>();
        public List<string> PreferredLanguages { get; set; } = new List<string>();
        public List<string> Encryption { get; set; } = new List<string>();
        public List<string> Policy { get; set; } = new List<string>();
        public List<string> Hiring { get; set; } = new List<string>();

        // Fields that should only appear once as string
        public string Canonical { get; set; }
        public string Expires { get; set; }
        public string SignatureEncryption { get; set; }


        internal InternalLogger Logger { get; set; }


        public async Task AnalyzeSecurityTxtRecord(string domainName, InternalLogger logger) {
            Logger = logger;

            Domain = domainName;

            string url = $"https://{domainName}/.well-known/security.txt";
            string response = await GetSecurityTxt(url);
            if (response == null) {
                url = $"http://{domainName}/security.txt";
                response = await GetSecurityTxt(url);
                FallbackUsed = true;
            }

            if (response != null) {
                RecordPresent = true;
                Url = url;
                ParseSecurityTxt(response);
            }
        }

        private async Task<string> GetSecurityTxt(string url) {
            try {
                using (HttpClient client = new HttpClient()) {
                    // Set the User-Agent header to mimic a popular web browser
                    client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537");

                    var response = await client.GetAsync(url);
                    if (response.IsSuccessStatusCode && response.Content.Headers.ContentType.MediaType == "text/plain") {
                        return await response.Content.ReadAsStringAsync();
                    } else {
                        return null;
                    }
                }
            } catch (Exception ex) {
                // Log the exception
                return null;
            }
        }


        private void ParseSecurityTxt(string txt) {
            var lines = txt.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            RecordValid = true;
            bool hasSeenCanonical = false;
            bool hasSeenExpires = false;
            bool hasSeenSignatureEncryption = false;

            foreach (var line in lines) {
                // Ignore comments
                if (line.StartsWith("#")) {
                    continue;
                }

                // Check if this line starts with a field name
                int colonIndex = line.IndexOf(':');
                if (colonIndex > 0) {
                    string currentField = line.Substring(0, colonIndex).Trim();
                    string value = line.Substring(colonIndex + 1).Trim();

                    // Add the value to the appropriate list in the record
                    switch (currentField) {
                        case "Contact":
                            if (value.StartsWith("mailto:")) {
                                ContactEmail.Add(value.Substring("mailto:".Length));
                            } else if (value.Contains("@")) {
                                ContactEmail.Add(value);
                            } else {
                                ContactWebsite.Add(value);
                            }
                            break;
                        case "Acknowledgments":
                            Acknowledgments.Add(value);
                            break;
                        case "Preferred-Languages":
                            PreferredLanguages.Add(value);
                            break;
                        case "Encryption":
                            Encryption.Add(value);
                            break;
                        case "Policy":
                            Policy.Add(value);
                            break;
                        case "Hiring":
                            Hiring.Add(value);
                            break;
                        case "-----BEGIN PGP SIGNED MESSAGE-----":
                            PGPSigned = true;
                            break;
                        case "Canonical":
                            if (hasSeenCanonical) {
                                Logger.WriteWarning("Multiple Canonical fields found");
                                RecordValid = false;
                            }
                            Canonical = value;
                            hasSeenCanonical = true;
                            break;
                        case "Expires":
                            if (hasSeenExpires) {
                                Logger.WriteWarning("Multiple Expires fields found");
                                RecordValid = false;
                            }
                            Expires = value;
                            hasSeenExpires = true;
                            break;
                        case "Signature-Encryption":
                            if (hasSeenSignatureEncryption) {
                                Logger.WriteWarning("Multiple Signature-Encryption fields found");
                                RecordValid = false;
                            }
                            SignatureEncryption = value;
                            hasSeenSignatureEncryption = true;
                            break;

                    }
                }
                if (!RecordValid) {
                    Logger.WriteWarning("Invalid security.txt file");
                }
            }
        }

    }
}
