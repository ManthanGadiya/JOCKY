# CHECKS FOR TEAMMATE LAPTOP (Docker-only)

Already done: Windows 11 + WSL2 Ubuntu-24.04 + Docker Desktop (WSL Integration ON)

Run:
wsl --list -v
docker --version
docker compose version
docker ps
docker run hello-world

Need: Free C: >10GB, D:\SIH 110GB free
No host LLVM/CMake/Java - all inside Dockerfile

Verify (no Docker needed):
python tools/jockyc.py examples/test.jocky -o build/a.ll --seed 1
python tools/jockyc.py examples/test.jocky --polymorphic -o build/b.ll --seed 2
certutil -hashfile build\a.ll SHA256
certutil -hashfile build\b.ll SHA256
# hashes differ = Point 1+2 pass

With Docker:
docker compose build
docker compose run --rm jocky bash -c "jockyc examples/test.jocky -o /tmp/a.ll && jockyc examples/test.jocky --polymorphic -o /tmp/b.ll && sha256sum /tmp/*.ll"
docker compose up  # frontend 3000, backend 8000/docs, nginx 80
