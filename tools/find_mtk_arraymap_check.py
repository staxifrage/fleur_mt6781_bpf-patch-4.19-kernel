#!/usr/bin/env python3
"""
Semantic locator for the MediaTek ALPS05247589 bounds check in
kernel/bpf/arraymap.c::array_map_update_elem() inside dump/kernel (raw AArch64 Image).

Target source pattern (MediaTek hunk):

    else {
        if (unlikely(sizeof(array->value) <
            array->elem_size * (index & array->index_mask)))
            return -EINVAL;
        memcpy(array->value + array->elem_size * (index & array->index_mask),
               value, map->value_size);
    }

struct bpf_array layout on this 4.19 build (derived from the reference signature:
`ldr w2, [x18, #0x20]` loads map.value_size while x18 = &array->map => member offsets
of bpf_array are offset by +0x20 relative to bpf_map):
    index_mask : bpf_map+0x18  -> array+0x38   (u32)
    elem_size  : bpf_map+0x28  -> array+0x48   (u64)
    value_size : bpf_map+0x20  -> array+0x40   (u32)
    max_entries: bpf_map+0x1c  -> array+0x3c   (u32)
    map_type   : bpf_map+0xc   -> array+0x2c   (u32)

Detection strategy (data-flow, not fixed bytes):
  For every conditional branch B in the text region:
    - walk a short window around B (before/after) collecting simple register defs
    - require within +/-24 insns of B:
        * ldr/ldur [Rn, #0x38] (index_mask load) followed by an `and` using it
        * ldr/ldur [Rn, #0x48] (elem_size load) feeding a mul/madd
        * the same masked-index product reused by a compare against a constant
          (cmp/cmn/subs #imm) OR another struct-derived value
        * a nearby `bl` whose target function looks like memcpy (large bl fan-in,
          cbz x2 early, byte/word copy loop)
        * a reachable error path materializing w0 = 0xFFFFFFEA (-EINVAL)
  Rank candidates and dump full disassembly for manual validation.
"""
import sys, struct
from collections import defaultdict
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

PATH = sys.argv[1] if len(sys.argv) > 1 else '/workspace/dump/kernel'
data = open(PATH, 'rb').read()
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

TEXT_START = 0x4000
TEXT_END   = 0x14d0000   # conservative; refine after mapping rodata start

# ---------------------------------------------------------------- decode pass
print('[*] linear disassembly ...', flush=True)
insns = {}
order = []
for i in md.disasm(data[TEXT_START:TEXT_END], TEXT_START):
    insns[i.address] = (i.mnemonic, i.op_str, bytes(i.bytes))
    order.append(i.address)
order.sort()
N = len(order)
addr2idx = {a: k for k, a in enumerate(order)}
print(f'[*] {N} instructions decoded', flush=True)

COND_BRANCHES = {'b.','b.<','b.<=','b.>','b.>=','b.eq','b.ne','cbz','cbnz','tbz','tbnz'}

def word_of(a):
    return data[a:a+4]

# ------------------------------------------------------------- memcpy finder
bl_targets = defaultdict(int)
for a,(m,o,b) in insns.items():
    if m == 'bl' and o.startswith('0x'):
        try: bl_targets[int(o.split()[0].rstrip(','),16)] += 1
        except: pass

memcpy_addrs = set()
for t,cnt in bl_targets.items():
    if cnt < 10 or t not in insns: continue
    body = [insns.get(t+4*k) for k in range(12)]
    if any(x is None for x in body): continue
    txt = ' '.join(f'{m} {o}' for m,o,_ in body)
    # kernel __memcpy__: cbz x2 near top, uses x3/x4 masking, has ret
    if ('cbz\tx2,' in txt or 'cbz x2,' in txt) and 'ret' in txt:
        memcpy_addrs.add(t)
print('[*] memcpy-like callees:', [hex(x) for x in sorted(memcpy_addrs)], flush=True)

# find all bl to those
bl_to_memcpy = set()
for a,(m,o,b) in insns.items():
    if m=='bl' and o.startswith('0x'):
        try:
            if int(o.split()[0].rstrip(','),16) in memcpy_addrs:
                bl_to_memcpy.add(a)
        except: pass
print(f'[*] bl memcpy sites: {len(bl_to_memcpy)}', flush=True)

# ------------------------------------------------------------ EINVAL epilogues
def defines_einval(a):
    """does instruction at `a` put 0xffffffea into w0/x0?"""
    if a not in insns: return False
    m,o,_ = insns[a]
    if m in ('mov','orr','movn','movz') and o.replace(' ','').startswith('w0,#'):
        try:
            v=int(o.split('#')[1].split(',')[0],0)&0xffffffff
            if v==0xffffffea: return True
        except: pass
    if m=='neg' and o.replace(' ','')=='w0,w21': return True
    return False

einval_defs = {a for a in insns if defines_einval(a)}
print(f'[*] mov w0,#-EINVAL sites: {len(einval_defs)}', flush=True)

# ------------------------------------------------------------------ helpers
import re
LD_RE = re.compile(r'^ldr\s+(?P<rt>[wx]\d+)\s*,\s*\[\s*(?P<rn>[wx]\d+)(?:,\s*#(?P<imm>0x[0-9a-f]+|\d+))?\]$')
LDUR_RE = re.compile(r'^ldur\s+(?P<rt>[wx]\d+)\s*,\s*\[\s*(?P<rn>[wx]\d+)(?:,\s*#(?P<imm>-?(?:0x[0-9a-f]+|\d+)))?\]$')
LDP_RE  = re.compile(r'^ldp\s+(?P<rt>[wx]\d+),(?P<rt2>[wx]\d+)\s*,\s*\[\s*(?P<rn>[wx]\d+)(?:,\s*#(?P<imm>-?(?:0x[0-9a-f]+|\d+)))?\]$')
AND_RE  = re.compile(r'^and\s+(?P<rd>[wx]\d+)\s*,\s*(?P<r1>[wx]\d+)\s*,\s*(?P<r2>[wx]\d+)$')
MUL_RE  = re.compile(r'^(mul|madd)\s+(?P<rd>[wx]\d+)\s*,\s*(?P<r1>[wx]\d+)\s*,\s*(?P<r2>[wx]\d+)')
CMP_RE  = re.compile(r'^(cmp|cmn|subs?)\s+.*#(?P<imm>0x[0-9a-f]+|\d+)\s*$')

def parse_imm(s):
    s=s.strip()
    neg = s.startswith('-')
    s=s.lstrip('-')
    v=int(s,0)
    return -v if neg else v

def scan_window(center_idx, back=40, fwd=40):
    lo=max(0,center_idx-back); hi=min(N-1,center_idx+fwd)
    feats={'mask_ld':[], 'elem_ld':[], 'ands':[], 'muls':[], 'cmps':[], 'bl_memcpy':[], 'einval':[]}
    for k in range(lo,hi+1):
        a=order[k]; m,o,_=insns[a]
        mm=LD_RE.match(f'{m} {o}') or LDUR_RE.match(f'{m} {o}')
        if mm:
            imm = mm.group('imm')
            v = parse_imm(imm) if imm else 0
            if v==0x38: feats['mask_ld'].append((a,mm.group('rt')))
            if v==0x48: feats['elem_ld'].append((a,mm.group('rt')))
        mm=LDP_RE.match(f'{m} {o}')
        if mm:
            imm=mm.group('imm'); v=parse_imm(imm) if imm else 0
            if v in (0x30,0x38,0x40,0x48,0x50): feats.setdefault('ldp',[]).append((a,v,mm.groups()))
        for rx,key in ((AND_RE,'ands'),(MUL_RE,'muls')):
            mm=rx.match(f'{m} {o}')
            if mm: feats[key].append((a,mm.groupdict()))
        mm=CMP_RE.match(f'{m} {o}')
        if mm: feats['cmps'].append((a,m,mm.group('imm')))
        if a in bl_to_memcpy: feats['bl_memcpy'].append(a)
        if a in einval_defs: feats['einval'].append(a)
    return feats

results=[]
cond_list=[a for a in order if insns[a][0] in COND_BRANCHES]
print(f'[*] conditional branches: {len(cond_list)}', flush=True)

for a in cond_list:
    idx=addr2idx[a]
    f=scan_window(idx)
    if not f['mask_ld'] or not f['elem_ld']: continue
    # require and fed by mask load reg
    mask_regs={r for _,r in f['mask_ld']}
    elem_regs={r for _,r in f['elem_ld']}
    and_ok=any(d['r2'] in mask_regs or d['r1'] in mask_regs for _,d in f['ands'])
    mul_ok=any(d['r1'] in elem_regs or d['r2'] in elem_regs or d['rd'] in elem_regs for _,d in f['muls'])
    if not (and_ok and mul_ok): continue
    score = (bool(f['bl_memcpy']), bool(f['cmps']), bool(f['einval']))
    results.append((score,a,f))

results.sort(key=lambda x:(x[0],x[1]), reverse=True)
print(f'[*] structural candidates: {len(results)}', flush=True)
with open('/tmp/work/candidates.txt','w') as fh:
    for score,a,f in results[:60]:
        fh.write(f'\n==== candidate branch @ {a:#x} ({insns[a][0]} {insns[a][1]}) score={score}\n')
        lo=max(0,addr2idx[a]-45); hi=min(N-1,addr2idx[a]+45)
        for k in range(lo,hi+1):
            ad=order[k]; m,o,bb=insns[ad]
            mark='  >>' if ad==a else ('   $' if ad in bl_to_memcpy else '')
            fh.write(f'{mark} {ad:#08x}: {bb.hex()} {m} {o}\n')
print('[*] wrote /tmp/work/candidates.txt')
