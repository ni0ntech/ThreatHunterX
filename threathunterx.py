# threathunterx.py

from ioc import IPIOC, DomainIOC, HashIOC

class ThreatHunterX:
    def __init__(self, iocs):
        self.raw_iocs = iocs
        self.processed_iocs = []

    def classify(self, ioc):
        if self._is_ip(ioc):
            return IPIOC(ioc)
        elif self._is_domain(ioc):
            return DomainIOC(ioc)
        elif self._is_hash(ioc):
            return HashIOC(ioc)
        else:
            raise ValueError(f"Unknown IOC format: {ioc}")

    def run(self):
        print("🔍 Enriching IOCs...")
        for raw in self.raw_iocs:
            try:
                ioc_obj = self.classify(raw)
                ioc_obj.enrich()
                self.processed_iocs.append(ioc_obj)
                print(f"✅ {raw} → Risk Score: {ioc_obj.risk_score}")
                print(f"Raw Enrichment Data for {raw}: {ioc_obj.enrichment_data}")
            except Exception as e:
                print(f"❌ Failed to process {raw}: {e}")

    def _is_ip(self, val):
        return val.count('.') == 3 and all(x.isdigit() for x in val.split('.') if x.isdigit())

    def _is_domain(self, val):
        return '.' in val and not self._is_ip(val)

    def _is_hash(self, val):
        return len(val) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in val)

# Example run
if __name__ == "__main__":
    iocs = ["8.8.8.8", "malicious.com", "44d88612fea8a8f36de82e1278abb02f"]
    hunter = ThreatHunterX(iocs)
    hunter.run()
