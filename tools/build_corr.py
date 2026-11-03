"""Generates Sigma correlation rules (rules/correlation/)."""
import yaml, uuid, os, json
NS = uuid.UUID("c0ffee00-0000-4000-8000-000000000001")
AUTHOR = "Habebur Rahman, FRIEND_NAME_HERE (Cyberion Defense Labs - Detection Engineering)"
C = [
 dict(cid="COR-001", name="uac_bypass_chain", title="UAC Bypass Chain: Registry Hijack Followed by Elevated Interpreter",
  desc="Correlates a UAC-bypass registry handler hijack with an auto-elevating binary spawning an interpreter on the same host within 5 minutes. Combining both stages gives near-certain confidence compared with either rule alone.",
  tags=["attack.privilege-escalation","attack.t1548.002"], type="temporal_ordered", rules=["uac_bypass_registry_hijack","autoelevate_binary_spawns_shell"], gb=["Computer"], span="5m",
  fps=["Software that edits shell-handler keys and launches an elevated binary immediately (very rare)"], level="critical"),
 dict(cid="COR-002", name="injection_burst", title="Process Injection Burst: Repeated Remote Thread Creation from One Source",
  desc="Detects five or more suspicious CreateRemoteThread events from the same source image within one minute, characteristic of reflective injection frameworks looping through targets or migrating payloads.",
  tags=["attack.stealth","attack.t1055"], type="event_count", rules=["remote_thread_injection"], gb=["Computer","SourceImage"], span="1m", cond={"gte":5},
  fps=["Security products performing bulk instrumentation"], level="high"),
 dict(cid="COR-003", name="lsass_access_with_injection", title="Credential Dumping via Injection: LSASS Access Plus Remote Thread",
  desc="Correlates suspicious LSASS memory access with a remote thread into a commonly injected process on the same host within one minute, as seen when Meterpreter hashdump migrates and then reads LSASS.",
  tags=["attack.credential-access","attack.t1003.001","attack.t1055"], type="temporal", rules=["lsass_suspicious_access","remote_thread_injection"], gb=["Computer"], span="1m",
  fps=["Red-team exercises", "EDR self-test tooling"], level="critical"),
 dict(cid="COR-004", name="bits_download_then_scriptlet", title="Download via BITSAdmin Followed by Scriptlet Execution",
  desc="Correlates BITSAdmin transfer activity with regsvr32 scriptlet execution on the same host within 10 minutes, a typical ingress-tool-transfer then proxy-execution chain.",
  tags=["attack.command-and-control","attack.t1105","attack.t1197","attack.t1218.010"], type="temporal_ordered", rules=["bitsadmin_abuse","regsvr32_scriptlet_exec"], gb=["Computer"], span="10m",
  fps=["Installer frameworks combining BITS delivery and COM registration"], level="high"),
]
os.makedirs("rules/correlation", exist_ok=True)
for c in C:
    corr = {"type": c["type"], "rules": c["rules"], "group-by": c["gb"], "timespan": c["span"]}
    if "cond" in c: corr["condition"] = c["cond"]
    d = {"title": c["title"], "id": str(uuid.uuid5(NS, c["cid"])), "name": c["name"], "status": "experimental", "description": c["desc"],
         "references": ["https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md"],
         "author": AUTHOR, "date": "2026-11-03", "tags": c["tags"], "correlation": corr, "falsepositives": c["fps"], "level": c["level"]}
    yaml.dump(d, open(f"rules/correlation/{c['cid']}_{c['name']}.yml", "w"), sort_keys=False, width=1000)
json.dump([{k: c[k] for k in ("cid","name","title","type","rules","span","level","fps")} for c in C], open("rules/correlation/_meta.json","w"), indent=1)
print(len(C), "correlation rules written")
