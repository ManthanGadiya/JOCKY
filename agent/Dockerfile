FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY agent/src/agent.cpp /tmp/agent.cpp
# Build stub agent (no heavy deps) - real build uses jocky build stage
RUN apt-get update && apt-get install -y g++ && g++ -O2 /tmp/agent.cpp -o /app/agent && rm -rf /var/lib/apt/lists/* || echo "agent stub"
CMD ["./agent", "--scan"]
