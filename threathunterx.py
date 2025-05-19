
from db import init_db, get_ioc, save_ioc
from ioc import IPIOC, DomainIOC, HashIOC
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

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
        console.print(Panel("🔍 [bold cyan]Enriching IOCs...[/bold cyan]", expand=False))

        table = Table(title="ThreatHunterX Results", box=box.SQUARE, show_lines=True)
        table.add_column("IOC", style="bold white")
        table.add_column("Type", style="magenta")
        table.add_column("Score", justify="right", style="yellow")
        table.add_column("Severity", style="bold red")
        table.add_column("Details", style="dim")

        for raw in self.raw_iocs:
            try:
                cached = get_ioc(raw)
                if cached:
                    ioc_obj = self.classify(raw)
                    ioc_obj.risk_score = cached["risk_score"]
                    ioc_obj.enrichment_data = cached["enrichment_data"]
                    self.processed_iocs.append(ioc_obj)
                    source = "[blue]CACHED[/blue]"
                else:
                    ioc_obj = self.classify(raw)
                    ioc_obj.enrich()
                    self.processed_iocs.append(ioc_obj)
                    save_ioc(ioc_obj)
                    source = "[green]LIVE or EXPIRED[/green]"


                score = ioc_obj.risk_score
                enrichment = ioc_obj.enrichment_data
                severity = self.get_severity(score)
                ioc_type = type(ioc_obj).__name__.replace("IOC", "")
                details = f"Detected by {enrichment.get('vt_positives', '?')} of {enrichment.get('total_engines', '?')}"

                table.add_row(raw, ioc_type, str(score), severity, f"{details} • {source}")

            except Exception as e:
                console.print(f"[bold red]❌ Failed to process {raw}:[/bold red] {e}")


        console.print(table)

    def get_severity(self, score):
        if score == 0:
            return "[green]Clean[/green]"
        elif score <= 5:
            return "[yellow]Low[/yellow]"
        elif score <= 25:
            return "[orange3]Medium[/orange3]"
        else:
            return "[red]High[/red]"

    def _is_ip(self, val):
        return val.count('.') == 3 and all(x.isdigit() for x in val.split('.') if x.isdigit())

    def _is_domain(self, val):
        return '.' in val and not self._is_ip(val)

    def _is_hash(self, val):
        return len(val) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in val)

# Example run
if __name__ == "__main__":
    init_db()
    iocs = ["8.8.8.8", "malicious.com", "44d88612fea8a8f36de82e1278abb02f"]
    hunter = ThreatHunterX(iocs)
    hunter.run()
