#!/usr/bin/env python3
# encrypt.py - string literal XOR encrypt (Point 2)
import random, re, sys, base64
seed = int(sys.argv[1]) if len(sys.argv)>1 else random.randint(0, 2**31)
random.seed(seed)
key = random.randint(1,255)
src = open(sys.argv[2]).read() if len(sys.argv)>2 else sys.stdin.read()
def enc(m):
    s=m.group(1)
    x=''.join(chr(ord(c)^key) for c in s)
    b=base64.b64encode(x.encode()).decode()
    return f'decrypt("{b}",{key})'
src = re.sub(r'"([^"]*)"', enc, src)
print(src)
