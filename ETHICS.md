# ETHICS - Weapon vs Detection

## What PS describes (Attacker story - context)
Polymorphism, hollowing, reflective DLL, BYOVD RTCore64, domain fronting.

## What we BUILD (Detector - ethical)
- Polymorphism: 3 hashes from benign test.jocky via LLVM passes inside Docker, not malware.
- Hollowing/BYOVD: testdata/*.json synthetic, YARA hits, no real NtUnmapViewOfSection or .sys load.
- CDN: Nginx proxy inside jocky-net, not real fronting abuse.

**PPT phrase:** Adversary emulation on controlled synthetic data - detection only, no kernel exploitation or EDR disabling on host. Behavioural detection (YARA+Sigma+Risk) inside Docker.

## Hazard if weaponized live (needs VM)
Real hollowing/ BYOVD = Defender quarantine / BSOD, needs isolated VM + snapshots + host-only. We DON'T do this.

## For SIH
One docker compose up, 3 hashes -> 1 Finding, Graph/Risk/MITRE/PDF proves detection.
