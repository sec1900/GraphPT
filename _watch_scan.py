import requests, time
A = "asset:baidu-test"
BASE = "http://localhost:8080"
start = time.time()
last = ""
while True:
    time.sleep(15)
    try:
        r = requests.get(BASE + "/api/scan/state?asset_id=" + A, timeout=10)
        s = r.json()["data"]
        elapsed = int(time.time() - start)
        rd = s.get("round", "?")
        cum = s.get("cumulative", {}) or {}
        pct = 0
        if cum.get("total_estimate"):
            pct = round(cum.get("scanned",0) / max(1, cum.get("total_estimate",1)) * 100)
        msg = "[%dm%02ds] R=%s L=%s %s %s/%s %d%% [%s]" % (elapsed//60, elapsed%60, rd, s.get("layer","-"), s.get("tool","-") or "", s.get("tools_done","?"), s.get("tools_total","?"), pct, s["status"])
        if msg != last:
            print(msg, flush=True)
            last = msg
        if s["status"] in ("done", "aborted", "idle", "partial"):
            print(">>> DONE: rounds=%s scanned=%s" % (s.get("round","?"), cum.get("scanned","?")), flush=True)
            r = requests.get(BASE + "/api/report?asset_id=" + A, timeout=15)
            for line in r.text.split("\n")[:15]:
                print("  " + line, flush=True)
            break
    except Exception as e:
        print("  err: %s" % e, flush=True)
