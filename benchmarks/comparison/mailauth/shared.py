"""Measure a shared Hickory resolver with answer caching still disabled."""
import json
import subprocess
from run import ROOT, KEYS, stats

with (ROOT / "mailauth/shared.jsonl").open("x") as out:
    for scenario in ["simple", "include", "chain0"]:
        for workers in [4, 16, 64]:
            for repeat in range(1, 4):
                before = stats()
                cmd = [str(ROOT / "mailauth/target/release/spf-mailauth-bench"), scenario, str(workers), "2", "shared"]
                result = json.loads(subprocess.check_output(cmd, text=True))
                after = stats()
                result["repeat"] = repeat
                result["dns_delta"] = {k: after[k] - before[k] for k in KEYS}
                assert result["errors"] == 0 and result["n"] > 0, result
                assert result["dns_delta"]["total.num.queries"] == result["dns_delta"]["total.num.cachehits"] > 0, result
                assert all(result["dns_delta"][k] == 0 for k in KEYS[2:]), result
                result["dns_queries_per_check_including_warmup"] = result["dns_delta"]["total.num.queries"] / (result["n"] + 100)
                out.write(json.dumps(result) + "\n")
                out.flush()
                print(scenario, workers, repeat, round(result["qps"]), result["dns_queries_per_check_including_warmup"], flush=True)
