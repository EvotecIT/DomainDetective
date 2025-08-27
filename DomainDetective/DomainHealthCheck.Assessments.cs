using System.Collections.Generic;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Aggregated assessments collected from all analyses that expose them.
        /// </summary>
        public IEnumerable<Assessment> GetAllAssessments() {
            // DNS / policy
            if (DmarcAnalysis is IHasAssessments dm) foreach (var a in dm.Assessments) yield return a;
            if (SpfAnalysis   is IHasAssessments sp) foreach (var a in sp.Assessments) yield return a;
            if (DKIMAnalysis  is IHasAssessments dk) foreach (var a in dk.Assessments) yield return a;
            if (MXAnalysis    is IHasAssessments mx) foreach (var a in mx.Assessments) yield return a;
            if (CAAAnalysis   is IHasAssessments ca) foreach (var a in ca.Assessments) yield return a;
            if (NSAnalysis    is IHasAssessments ns) foreach (var a in ns.Assessments) yield return a;
            if (DaneAnalysis  is IHasAssessments da) foreach (var a in da.Assessments) yield return a;
            if (DnsSecAnalysis is IHasAssessments ds) foreach (var a in ds.Assessments) yield return a;
            if (MTASTSAnalysis is IHasAssessments ms) foreach (var a in ms.Assessments) yield return a;
            if (TLSRPTAnalysis is IHasAssessments tr) foreach (var a in tr.Assessments) yield return a;
            if (BimiAnalysis   is IHasAssessments bi) foreach (var a in bi.Assessments) yield return a;
            if (ReverseDnsAnalysis is IHasAssessments rd) foreach (var a in rd.Assessments) yield return a;
            if (FcrDnsAnalysis is IHasAssessments fr) foreach (var a in fr.Assessments) yield return a;
            if (WhoisAnalysis is IHasAssessments wh) foreach (var a in wh.Assessments) yield return a;
            if (RdapAnalysis is IHasAssessments ra) foreach (var a in ra.Assessments) yield return a;
            if (OpenResolverAnalysis is IHasAssessments or) foreach (var a in or.Assessments) yield return a;
            if (ZoneTransferAnalysis is IHasAssessments zt) foreach (var a in zt.Assessments) yield return a;
            if (StartTlsAnalysis is IHasAssessments st) foreach (var a in st.Assessments) yield return a;
            if (SmtpTlsAnalysis is IHasAssessments sm) foreach (var a in sm.Assessments) yield return a;
            if (SmtpBannerAnalysis is IHasAssessments sb) foreach (var a in sb.Assessments) yield return a;
            if (ImapTlsAnalysis is IHasAssessments it) foreach (var a in it.Assessments) yield return a;
            if (Pop3TlsAnalysis is IHasAssessments pt) foreach (var a in pt.Assessments) yield return a;
            if (OpenRelayAnalysis is IHasAssessments orl) foreach (var a in orl.Assessments) yield return a;
            if (DNSBLAnalysis is IHasAssessments dbl) foreach (var a in dbl.Assessments) yield return a;
            if (RpkiAnalysis is IHasAssessments rp) foreach (var a in rp.Assessments) yield return a;
            if (HttpAnalysis is IHasAssessments http) foreach (var a in http.Assessments) yield return a;
            if (SecurityTXTAnalysis is IHasAssessments sec) foreach (var a in sec.Assessments) yield return a;
            if (RobotsTxtAnalysis is IHasAssessments rbt) foreach (var a in rbt.Assessments) yield return a;
            if (SOAAnalysis is IHasAssessments soa) foreach (var a in soa.Assessments) yield return a;
            if (AutodiscoverAnalysis is IHasAssessments ad) foreach (var a in ad.Assessments) yield return a;
            if (AutodiscoverHttpAnalysis is IHasAssessments adh) foreach (var a in adh.Assessments) yield return a;
            if (DnsTtlAnalysis is IHasAssessments ttl) foreach (var a in ttl.Assessments) yield return a;
            if (PortAvailabilityAnalysis is IHasAssessments pav) foreach (var a in pav.Assessments) yield return a;
            if (PortScanAnalysis is IHasAssessments psc) foreach (var a in psc.Assessments) yield return a;
            if (SnmpAnalysis is IHasAssessments snm) foreach (var a in snm.Assessments) yield return a;
            if (IPNeighborAnalysis is IHasAssessments ipn) foreach (var a in ipn.Assessments) yield return a;
            if (DnsTunnelingAnalysis is IHasAssessments tun) foreach (var a in tun.Assessments) yield return a;
            if (TyposquattingAnalysis is IHasAssessments t) foreach (var a in t.Assessments) yield return a;
            if (FlatteningServiceAnalysis is IHasAssessments fl) foreach (var a in fl.Assessments) yield return a;
            if (WildcardDnsAnalysis is IHasAssessments wi) foreach (var a in wi.Assessments) yield return a;
            if (TakeoverCnameAnalysis is IHasAssessments to) foreach (var a in to.Assessments) yield return a;
            if (DirectoryExposureAnalysis is IHasAssessments de) foreach (var a in de.Assessments) yield return a;
            if (ThreatIntelAnalysis is IHasAssessments thi) foreach (var a in thi.Assessments) yield return a;
            if (ThreatFeedAnalysis is IHasAssessments thf) foreach (var a in thf.Assessments) yield return a;
            if (MessageHeaderAnalysis is IHasAssessments mh) foreach (var a in mh.Assessments) yield return a;
            if (ArcAnalysis is IHasAssessments arc) foreach (var a in arc.Assessments) yield return a;
            if (DanglingCnameAnalysis is IHasAssessments dcn) foreach (var a in dcn.Assessments) yield return a;
        }
    }
}
