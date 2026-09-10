FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl python3 python3-urllib3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Keep C++ stub for reference (ARCHITECTURE.md §7) but primary transport is now Python via nginx per FORENSICS_SPEC §56
COPY agent/src/agent.cpp /tmp/agent.cpp
RUN apt-get update && apt-get install -y g++ && g++ -O2 /tmp/agent.cpp -o /app/agent && rm -rf /var/lib/apt/lists/* || echo "agent stub"
# Real agent: Python HTTP via nginx (SECURITY_MODEL §24, ARCHITECTURE §21)
COPY agent/agent.py /app/agent.py
RUN chmod +x /app/agent.py
# agent.py handles collection + transmit via BACKEND_URL=http://nginx:80 per docker-compose
CMD ["python3", "/app/agent.py", "--scan"]
