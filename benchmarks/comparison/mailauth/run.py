"""Run sequential paired trials on the prepared VM; fail on errors/cache misses."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
KEYS = ["total.num.queries", "total.num.cachehits", "total.num.cachemiss",
        "total.num.queries_ip_ratelimited", "num.query.ratelimited",
        "total.requestlist.exceeded", "total.requestlist.overwritten"]

def stats():
    data = subprocess.check_output(["sudo", "-n", "unbound-control", "stats_noreset"], text=True)
    return {k: float(v) for k, v in (line.split("=", 1) for line in data.splitlines())}

def trial(impl, scenario, workers, repeat):
    if impl == "go":
        cmd = [str(ROOT / "go-current"), "-mode", "spf", "-scenario", scenario,
               "-workers", str(workers), "-duration", "3s"]
    else:
        cmd = [str(ROOT / "mailauth/target/release/spf-mailauth-bench"), scenario, str(workers), "3"]
    before = stats()
    result = json.loads(subprocess.check_output(cmd, text=True, env={**os.environ, "GOMAXPROCS": "4"}))
    after = stats()
    result.update(implementation=impl, repeat=repeat)
    result["dns_delta"] = {k: after[k] - before[k] for k in KEYS}
    expected = (result["n"] + (100 if impl == "mail-auth" else 0)) * {"simple": 1, "include": 2, "chain0": 10}[scenario]
    result["expected_dns_queries"] = expected
    assert result["errors"] == 0 and result["n"] > 0, result
    assert result["dns_delta"]["total.num.queries"] == expected, result
    assert result["dns_delta"]["total.num.cachehits"] == expected, result
    assert all(result["dns_delta"][k] == 0 for k in KEYS[2:]), result
    assert result["p99_us"] < 100000, result
    return result

if __name__ == "__main__":
    # Exclusive creation prevents accidental replacement of an earlier run.
    with (ROOT / "mailauth/results.jsonl").open("x") as out:
        for scenario in ["simple", "include", "chain0"]:
            for workers in [1, 4, 16, 64]:
                for repeat in range(1, 4):
                    order = ["go", "mail-auth"] if repeat % 2 else ["mail-auth", "go"]
                    for impl in order:
                        result = trial(impl, scenario, workers, repeat)
                        out.write(json.dumps(result) + "\n")
                        out.flush()
                        print(impl, scenario, workers, repeat, round(result["qps"]), flush=True)
