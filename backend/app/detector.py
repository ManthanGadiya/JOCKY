# L7 Detection Engine - YARA + Sigma + Behavioral Risk 0-100
# YARA rule: JOCKY_DEMO_MARKER (safe, like EICAR for demo)
# Sigma: process tree anomaly, driver cert anomaly
# Behavioral: PPID_anomaly*30 + hollowed_mem*40 + driver_vuln*30
def score(evidence: dict) -> int:
    s=0
    if evidence.get("ppid_anomaly"): s+=30
    if evidence.get("hollowed"): s+=40
    if evidence.get("vulnerable_driver"): s+=30
    if evidence.get("unbacked_rx"): s+=25
    if evidence.get("reflective_dll"): s+=35
    return min(s, 100)

def yara_scan(content: str):
    hits=[]
    if "JOCKY_DEMO_MARKER" in content: hits.append("JOCKY_DEMO_MARKER")
    if "RTCore64" in content: hits.append("BYOVD_RTCore64")
    return hits
