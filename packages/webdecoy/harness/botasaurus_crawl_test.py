"""
F4 tripwire validation — the test botasaurus (or any fingerprint-stealth tool)
CANNOT pass.

A scraper that *crawls* — fetches a page, extracts links, follows them — will
request the hidden honeytoken decoy link and trip the tripwire. Unlike F1
fingerprinting (which botasaurus defeats), this catches *intent* (going where a
human can't), which stealth cannot spoof away.

    <venv>/bin/python harness/botasaurus_crawl_test.py

Run request mode (the exact mode that evaded F1). A real human/browser loads the
page but never follows the invisible link, so it is never flagged.
"""

import re

HARNESS = "http://localhost:8787"


def crawl() -> None:
    from botasaurus.request import request, Request

    @request
    def run(req: "Request", data):  # noqa: ANN001
        page = req.get(f"{HARNESS}/").text
        hrefs = re.findall(r'href="([^"]+)"', page)
        print(f"scraper extracted {len(hrefs)} link(s): {hrefs}")

        tripped = []
        for h in hrefs:
            url = h if h.startswith("http") else HARNESS + h
            r = req.get(url)
            flag = ""
            if r.status_code == 403:
                flag = "   <-- TRIPWIRE: BLOCKED"
                tripped.append(h)
            print(f"  GET {h}  ->  {r.status_code}{flag}")

        print(f"\nRESULT: {'CAUGHT (tripwire blocked the scraper)' if tripped else 'evaded'}"
              f" — tripwires hit: {tripped}")
        return tripped

    run()


if __name__ == "__main__":
    crawl()
