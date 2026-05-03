import pytest

from app import create_app
from app.extensions import db
from app.models import Scan, Finding
from app.scanner.engine import ScanEngine
from app.scanner.crawler import DiscoveredEndpoint, CrawlResult


class DummyCrawler:
    def __init__(self, endpoints):
        self._eps = endpoints

    def crawl(self, seed_url):
        return CrawlResult(seed_url=seed_url, endpoints=self._eps)


@pytest.fixture
def app():
    app = create_app("testing")
    yield app


def test_scan_engine_runs_and_persists_findings(app):
    with app.app_context():
        # Create an empty scan row
        scan = Scan(target_url="http://example.com")
        db.session.add(scan)
        db.session.commit()

        # prepare a fake discovered endpoint with a script in the body to trigger findings
        ep = DiscoveredEndpoint(
            url="http://example.com/",
            path="/",
            method="GET",
            evidence="seed",
            status_code=200,
            headers={"server": "nginx"},
            body="<html><script>alert(1)</script></html>",
        )

        engine = ScanEngine(app)
        # replace its crawler with our dummy
        engine.crawler = DummyCrawler([ep])

        result = engine.run(scan)

        # Ensure result includes the scan id and endpoints
        assert result["scan_id"] == scan.id
        assert len(result["endpoints"]) == 1

        # Findings should be persisted
        findings = Finding.query.filter_by(scan_id=scan.id).all()
        assert len(findings) > 0
        # ensure at least one finding has a title we expect
        titles = [f.title for f in findings]
        assert any("Inline <script> tag present" in t or "Missing Strict-Transport-Security" in t for t in titles)
