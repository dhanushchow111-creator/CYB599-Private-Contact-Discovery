"""Small, *insecure* educational ring-BFV-style implementation and binned PSI.

This is NOT Microsoft SEAL, APSI, or standardized BFV. In particular, the
small ring degrees and hand-chosen modulus confer no known security level.
"""
from __future__ import annotations
import hashlib, secrets, re, time
from dataclasses import dataclass

T = 65537
E164 = re.compile(r'^\+[1-9][0-9]{1,14}$')

def normalize(items):
    values = set()
    for x in items:
        if not isinstance(x, str) or not E164.fullmatch(x):
            raise ValueError('Must use canonical E.164 numbers')
        values.add(x)
    return sorted(values)

@dataclass(frozen=True)
class Config:
    name: str
    n: int
    bins: int
    max_clients: int
    max_server: int
    cap: int = 8
    parts: int = 3
    q: int = 2**120 - 17
    t: int = T

SMALL = Config('toy-A', 16, 16, 4, 12)
LARGE = Config('toy-B', 32, 32, 8, 24)

class Ring:
    def __init__(self, n, q): self.n, self.q = n, q
    def add(self,a,b): return [(x+y)%self.q for x,y in zip(a,b)]
    def neg(self,a): return [(-x)%self.q for x in a]
    def mul(self,a,b):
        # negacyclic polynomial multiplication in Z_q[X]/(X^N + 1)
        n,q=self.n,self.q; out=[0]*n
        for i,x in enumerate(a):
            if not x: continue
            for j,y in enumerate(b):
                if not y: continue
                k=i+j
                if k<n: out[k]+=x*y
                else: out[k-n]-=x*y
        return [x%q for x in out]
    def scale(self,a,k): return [(x*k)%self.q for x in a]
    def small(self): return [secrets.randbelow(3)-1 for _ in range(self.n)]
    def uniform(self): return [secrets.randbelow(self.q) for _ in range(self.n)]

@dataclass
class CT:
    a: list[int]
    b: list[int]

class BFVDemo:
    """Public-key BFV-like scheme; addition & plaintext scaling ONLY."""
    def __init__(self,cfg):
        self.cfg=cfg; self.r=Ring(cfg.n,cfg.q)
        self.delta=cfg.q//cfg.t
        self.sk=self.r.small()
        self.pk_a=self.r.uniform()
        self.pk_b=self.r.add(self.r.neg(self.r.mul(self.pk_a,self.sk)),self.r.small())
    def encrypt(self,m):
        if not 0<=m<self.cfg.t: raise ValueError('plaintext out of range')
        R=self.r
        u=R.small(); e0=R.small(); e1=R.small()
        a=R.add(R.add(R.mul(self.pk_b,u),e0), [self.delta*m]+[0]*(R.n-1))
        b=R.add(R.mul(self.pk_a,u),e1)
        return CT(a,b)
    def decrypt(self,c):
        v=self.r.add(c.a,self.r.mul(c.b,self.sk))[0]
        # centered representative, round-to-nearest then reduce mod t
        centered=v if v<=self.cfg.q//2 else v-self.cfg.q
        return ((centered*self.cfg.t+self.cfg.q//2)//self.cfg.q)%self.cfg.t
    def add(self,x,y): return CT(self.r.add(x.a,y.a),self.r.add(x.b,y.b))
    def scale(self,x,k): return CT(self.r.scale(x.a,k),self.r.scale(x.b,k))
    def add_plain(self,x,v):
        a=x.a.copy(); a[0]=(a[0]+self.delta*(v%self.cfg.t))%self.cfg.q
        return CT(a,x.b.copy())
    def ct_bytes(self): return 2*self.cfg.n*((self.cfg.q.bit_length()+7)//8)


def field_parts(s,parts):
    # Domain-separated independent field elements: NOT private when unencrypted.
    return [int.from_bytes(hashlib.sha256((f'CYB599/part/{j}/'+s).encode()).digest(), 'big') % (T-1)+1 for j in range(parts)]

def indexes(s,bins,seed):
    return [int.from_bytes(hashlib.sha256(f'{seed}/{j}/{s}'.encode()).digest()[:8],'big')%bins for j in range(3)]

def assign_cuckoo(xs,cfg,seed):
    # DFS augmenting-path assignment; never drop an occupied client item.
    bins=[None]*cfg.bins
    def insert(x,seen):
        for pos in indexes(x,cfg.bins,seed):
            if pos in seen: continue
            seen.add(pos)
            if bins[pos] is None or insert(bins[pos],seen):
                bins[pos]=x; return True
        return False
    for x in xs:
        if not insert(x,set()): raise ValueError('cuckoo placement failed; reseed')
    return bins

def polynomial(roots,t):
    # coefficients low-to-high of prod(Z-root) mod t
    c=[1]
    for root in roots:
        out=[0]*(len(c)+1)
        for j,v in enumerate(c):
            out[j]=(out[j]-root*v)%t
            out[j+1]=(out[j+1]+v)%t
        c=out
    return c

def evaluate(he,encrypted_powers,roots):
    c=polynomial(roots,he.cfg.t)
    if len(c)==1:
        # Encrypted constant avoids a plaintext-only response.
        return he.encrypt(1)
    result=he.scale(encrypted_powers[0],0)
    result=he.add_plain(result,c[0])
    for exponent,coefficient in enumerate(c[1:],start=1):
        # centered scalar avoids giant intermediate noise magnification
        k=coefficient if coefficient<=he.cfg.t//2 else coefficient-he.cfg.t
        result=he.add(result,he.scale(encrypted_powers[exponent-1],k))
    r=secrets.randbelow(he.cfg.t-1)+1
    signed=r if r<=he.cfg.t//2 else r-he.cfg.t
    return he.scale(result,signed)

def plaintext_baseline(xs,ys): return sorted(set(normalize(xs)) & set(normalize(ys)))

def run_psi(clients, registry, cfg, *, seed='public-seed', he=None):
    xs=normalize(clients); ys=normalize(registry)
    if len(xs)>cfg.max_clients or len(ys)>cfg.max_server: raise ValueError('public envelope exceeded')
    he=he or BFVDemo(cfg)
    start=time.perf_counter()
    placement=assign_cuckoo(xs,cfg,seed)
    server_bins=[[] for _ in range(cfg.bins)]
    for y in ys:
        for p in set(indexes(y,cfg.bins,seed)):
            server_bins[p].append(y)
    occupancy=max(map(len,server_bins))
    if occupancy>cfg.cap: raise ValueError('server bin overflow; cannot truncate')
    setup_s=time.perf_counter()-start
    start=time.perf_counter()
    # Encrypt every part and every power in public padded bin envelope.
    # Independent random dummy slots retain the transcript shape.
    powers=[]
    for value in placement:
        parts=field_parts(value,cfg.parts) if value is not None else [secrets.randbelow(cfg.t-1)+1 for _ in range(cfg.parts)]
        for v in parts:
            powers.append([he.encrypt(pow(v,k,cfg.t)) for k in range(1,cfg.cap+1)])
    query_s=time.perf_counter()-start
    start=time.perf_counter()
    responses=[]
    for pos,rows in enumerate(server_bins):
        for j in range(cfg.parts):
            roots=[field_parts(y,cfg.parts)[j] for y in rows]
            responses.append(evaluate(he,powers[pos*cfg.parts+j],roots))
    evaluation_s=time.perf_counter()-start
    start=time.perf_counter()
    matches=[]
    for i,value in enumerate(placement):
        if value is None: continue
        if all(he.decrypt(responses[i*cfg.parts+j])==0 for j in range(cfg.parts)):
            matches.append(value)
    recovery_s=time.perf_counter()-start
    num_upload=cfg.bins*cfg.parts*cfg.cap
    num_reply=cfg.bins*cfg.parts
    stats={'setting':cfg.name,'ring_degree':cfg.n,'plaintext_modulus':cfg.t,
      'q_bits':cfg.q.bit_length(),'bins':cfg.bins,'parts':cfg.parts,'cap':cfg.cap,
      'client_count':len(xs),'server_count':len(ys),'max_occupancy':occupancy,
      'query_ciphertexts':num_upload,'response_ciphertexts':num_reply,
      'ciphertext_bytes':he.ct_bytes(),'upload_bytes':num_upload*he.ct_bytes(),
      'download_bytes':num_reply*he.ct_bytes(), 'setup_s':setup_s,
      'query_s':query_s,'evaluation_s':evaluation_s,'recovery_s':recovery_s,
      'total_s':setup_s+query_s+evaluation_s+recovery_s,
      'proof_bytes':None,'security_bits':None}
    return sorted(matches), stats
