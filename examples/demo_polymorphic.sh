#!/usr/bin/env bash
# demo_polymorphic.sh - Point 1+2 proof (works with Docker OR host fallback)
set -e
echo "=== JOCKY Polymorphism Demo (3 builds, 3 hashes, 1 YARA cluster) ==="
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  echo "[Docker mode]"
  docker compose run --rm jocky bash -c "
    jockyc examples/test.jocky -o /tmp/a.ll --seed 1
    jockyc examples/test.jocky --polymorphic -o /tmp/b.ll --seed 2
    jockyc examples/test.jocky --polymorphic -o /tmp/c.ll --seed 3
    echo '--- SHA256 ---' && sha256sum /tmp/a.ll /tmp/b.ll /tmp/c.ll
    echo '--- CFG diff a vs b ---' && diff /tmp/a.ll /tmp/b.ll | head -20
    echo '--- YARA hits (all 3 should hit JOCKY_DEMO_MARKER) ---' && grep -c JOCKY_DEMO_MARKER /tmp/a.ll /tmp/b.ll /tmp/c.ll
  "
else
  echo "[Host fallback - no Docker]"
  python tools/jockyc.py examples/test.jocky -o /tmp/a.ll --seed 1
  python tools/jockyc.py examples/test.jocky --polymorphic -o /tmp/b.ll --seed 2
  python tools/jockyc.py examples/test.jocky --polymorphic -o /tmp/c.ll --seed 3
  echo "--- SHA256 ---" && sha256sum /tmp/a.ll /tmp/b.ll /tmp/c.ll || certutil -hashfile /tmp/a.ll SHA256
  echo "--- CFG diff ---" && diff /tmp/a.ll /tmp/b.ll | head -20 || fc /tmp/a.ll /tmp/b.ll
fi
