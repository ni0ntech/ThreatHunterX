# ioc.py

from abc import ABC, abstractmethod
from enricher import vt_lookup_ip, vt_lookup_domain, vt_lookup_hash

class IOC(ABC):
    def __init__(self, value):
        self.value = value
        self.enrichment_data = {}
        self.risk_score = 0

    @abstractmethod
    def enrich(self):
        pass

class IPIOC(IOC):
    def enrich(self):
        self.enrichment_data = vt_lookup_ip(self.value)
        self.risk_score = self.enrichment_data.get("vt_positives", 0)

class DomainIOC(IOC):
    def enrich(self):
        self.enrichment_data = vt_lookup_domain(self.value)
        self.risk_score = self.enrichment_data.get("vt_positives", 0)

class HashIOC(IOC):
    def enrich(self):
        self.enrichment_data = vt_lookup_hash(self.value)
        self.risk_score = self.enrichment_data.get("vt_positives", 0)
