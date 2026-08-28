#!/usr/bin/env python3
# rename.py - variable/function rename before IRGen (Point 2)
import random, re, sys, hashlib
seed = int(sys.argv[1]) if len(sys.argv)>1 else random.randint(0, 2**31)
random.seed(seed)
src = open(sys.argv[2]).read() if len(sys.argv)>2 else sys.stdin.read()
# rename let variables to v_<rand>
vars_found = re.findall(r'\blet\s+(\w+)', src)
mapping = {v: f"v_{random.randint(1000,9999)}_{hashlib.md5(v.encode()).hexdigest()[:4]}" for v in vars_found}
for k,v in mapping.items():
    src = re.sub(r'\b'+re.escape(k)+r'\b', v, src)
print(src)
# mapping printed to stderr for audit
import sys as _sys
print(f"; rename seed={seed} map={mapping}", file=_sys.stderr)
