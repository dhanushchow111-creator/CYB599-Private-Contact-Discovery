from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch
import csv, statistics, platform, math, os
from pathlib import Path
root=Path(__file__).parent
raw=list(csv.DictReader(open(root/'results/bfv_measurements.csv')))
groups={s:[r for r in raw if r['setting']==s] for s in ['toy-A','toy-B']}
styles=getSampleStyleSheet();styles.add(ParagraphStyle(name='TitleAlt',parent=styles['Title'],fontName='Helvetica-Bold',fontSize=17,leading=21,spaceAfter=10))
styles.add(ParagraphStyle(name='H1x',parent=styles['Heading1'],fontSize=12.8,leading=16,textColor=colors.HexColor('#16385E'),spaceBefore=7,spaceAfter=7))
styles.add(ParagraphStyle(name='Bodyx',parent=styles['BodyText'],fontSize=9.3,leading=14,spaceAfter=8))
styles.add(ParagraphStyle(name='Smallx',parent=styles['BodyText'],fontSize=8,leading=11,spaceAfter=5))
styles.add(ParagraphStyle(name='Captionx',parent=styles['BodyText'],fontSize=8.5,leading=11,spaceAfter=9,textColor=colors.HexColor('#455468')))
story=[]
def p(t,sty='Bodyx'):story.append(Paragraph(t,styles[sty]))
def h(t):p(t,'H1x')
def table(rows,widths=None):
 t=Table([[Paragraph(str(v),styles['Smallx']) for v in row] for row in rows],colWidths=widths,repeatRows=1,hAlign='LEFT')
 t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#E6EEF6')),('VALIGN',(0,0),(-1,-1),'TOP'),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#F5F8FB')]),('BOTTOMPADDING',(0,0),(-1,-1),7),('TOPPADDING',(0,0),(-1,-1),7),('LINEBELOW',(0,0),(-1,0),0.6,colors.HexColor('#A3B5C7'))]));story.append(t);story.append(Spacer(1,12))
def page():story.append(PageBreak())
def med(r,k):return statistics.median(float(a[k]) for a in r)
def p95(r,k):return sorted(float(a[k]) for a in r)[math.ceil(.95*len(r))-1]

def milliseconds(x):return f'{x*1000:.3f}'

# Page 1
p('CYB 599 Graduate Project — Part 3','TitleAlt')
p('Implementation &amp; Evaluation: Educational BFV-Style Binned Private Contact Discovery','H1x')
p('Dhanush Krishna Chowdari Midamanuru | November 2026 | Seven-page evaluation report','Captionx')
h('Executive summary and claim boundary')
p('The original Part 2 design proposed unbalanced private set intersection for contact discovery with BFV, cuckoo hashing, six encoded field parts, a large padded table, and a semi-honest threat model. This Part 3 artifact implements a <b>functional, small-scale BFV-style ring-encryption prototype</b> with encrypted polynomial membership tests, cuckoo binning, independent response masks, shape padding, correctness tests, and real benchmarks. It is not Microsoft SEAL or Microsoft APSI. No production cryptographic security is claimed.')
h('Delivered evidence')
table([['Criterion','Evidence in archive'],['Working implementation','src/bfv_demo.py; single-command run.sh; 16 passing tests'],['Reproducible evaluation','benchmark.py; ten timing repetitions for each of two toy configurations; CSV/JSON'],['Baseline','Measured plain-text set intersection with identical synthetic sets'],['Limitations','Pages 5–6 distinguish unimplemented claims from actual guarantees']], [125,390])
h('Functional objective')
p('Let X be the client address book and Y be the server registry. Under honest local execution, return only the synthetic-number intersection X ∩ Y to the client. The server is given encrypted query powers, never clear input numbers. All padded bins, powers and response ciphertext counts follow a public envelope. Evaluation is local simulation of both parties, rather than a deployed network service.')
h('Immediate result')
p('Both toy configurations passed the end-to-end comparison against plaintext set intersection. Unit tests passed 16/16. The experiment uses synthetic phone-number inputs exclusively and reports serialized ciphertext bytes, measured execution latency, and the non-private comparison. The original larger BFV/APSI security and scalability objectives remain unverified.')
page()
# Page 2
h('1. Protocol and implementation architecture')
p('Inputs are normalized to a strict E.164-like canonical string form and deduplicated. Three public hash choices map each client item into B bins. A DFS augmenting-path cuckoo placement ensures at most one real client item per occupied bin; failure causes an explicit exception, never silent omission. Empty client slots are independently sampled dummy field values. Server items are inserted into every one of their three candidate bins, and any bin exceeding its publicly configured degree cap is rejected.')
p('Each item is encoded using three independently domain-separated SHA-256-derived field elements modulo t = 65537. This domain-separated hash is <b>not</b> a private token on its own: phone-number values are enumerable. Query privacy in this local proof of concept depends on encrypted polynomial values, and no practical security strength is established for the toy ring settings.')
h('Toy ring-BFV-style arithmetic')
p('The implementation uses Rq = Zq[X]/(X^N+1), with secret small ternary polynomial s, public pair (b, a) where b = -a·s + e, and Δ = floor(q/t). Encryption of constant message m computes (b·u + e0 + Δm, a·u + e1) in Rq². Decryption reduces c0 + s·c1, rounds a centered constant coefficient by t/q, then reduces modulo t. Ciphertext addition and plaintext-scalar multiplication are implemented; ciphertext-ciphertext multiplication and relinearization are intentionally absent.')
h('Encrypted membership evaluation')
p('A server-bin polynomial for field part j is Pj(Z) = ∏(Z − aij) over the finite field Ft. For each padded client bin the client encrypts powers z¹ ... z⁸. With plaintext coefficients c0 ... cd, the server evaluates Enc(Pj(z)) by adding the constant coefficient and a linear combination of encrypted powers. It multiplies each part response by an independently random nonzero mask rj. The client locally decrypts and accepts an occupied bin only if <b>all three</b> field-part results are zero. This still permits mixed-root false positives and lacks a formal probability bound.')
h('Transcript design')
p('Each query always includes B × 3 × 8 ciphertexts. The server always returns B × 3 ciphertexts; one fixed public partition per bin is supported. A larger-than-cap bin aborts. No network messaging, proofs, authentication or traffic metadata are implemented.')
page()
# Page 3
h('2. Experimental methodology and configurations')
p('The run script executes unittest discovery, followed by ten independent measured runs for each of two tiny configurations, after one warmup. Each measured run creates a new encryption key and evaluates the padded query envelope. The baseline computes direct plaintext set intersection over the same canonicalized synthetic inputs. Tests fail if private and baseline intersections differ. Measurements use time.perf_counter() and report end-to-end setup, encryption, evaluation and recovery. Output is recorded as raw CSV and JSON with Python and OS metadata.')
table([['Parameter','toy-A','toy-B'],['Ring dimension N','16','32'],['Modulus q','2^120 − 17','2^120 − 17'],['Plaintext modulus t','65537','65537'],['Cuckoo bins B','16','32'],['Client / server records','4 / 12','8 / 24'],['Field parts / cap','3 / 8','3 / 8'],['Query ciphertexts','384','768'],['Response ciphertexts','48','96'],['Timing repetitions','10','10']], [245,130,130])
h('Why these are not BFV security settings')
p('Small N = 16 or 32 makes the system computationally tractable in pure Python, but is far below the ring dimensions required for credible lattice-based cryptographic security. Although the polynomial and rounding structure resemble a BFV public-key scheme, the parameters have not been validated against the Homomorphic Encryption Standard, q was hand-selected, security checks are absent, and no 128-bit security estimate can be asserted. The two settings are <b>functional configuration experiments</b>, not secure cryptographic parameter sets.')
h('Measurement controls')
p('Only synthetic E.164-like numbers are used; they are intentionally too small to represent full service-scale contact discovery. No fixed CPU frequency, physical RAM ceiling, server deployment or cross-machine networking was controlled. Timing numbers therefore characterize this one container run only, and cannot predict the original Part 2 n ≥ 65,536 feasibility targets.')
page()
# Page 4
h('3. Results: correctness, latency, and sizes')
p('The raw artifact contains 20 measured protocol trials and plaintext-baseline measurements. All 20 measured intersection results equaled the non-private baseline. A separate unittest suite passed 16/16 tests, covering roundtrip encryption, ciphertext randomization, homomorphic addition, scalar multiplication, polynomial zero/nonzero tests, empty/full/mixed matches, duplicates, malformed input, envelope errors and fixed transcript dimensions.')
rows=[['Metric','toy-A','toy-B']]
for label,key in [('Median total (ms)','total_s'),('p95 total (ms)','total_s'),('Median encryption (ms)','query_s'),('Median server evaluation (ms)','evaluation_s'),('Median recovery (ms)','recovery_s'),('Median plaintext baseline (ms)','baseline_s')]:
 rows.append([label,milliseconds(p95(groups['toy-A'],key) if label.startswith('p95') else med(groups['toy-A'],key)),milliseconds(p95(groups['toy-B'],key) if label.startswith('p95') else med(groups['toy-B'],key))])
table(rows,[240,132,132])
table([['Communication and artifacts','toy-A','toy-B'],['Ciphertext representation (bytes)',groups['toy-A'][0]['ciphertext_bytes'],groups['toy-B'][0]['ciphertext_bytes']],['Encrypted upload bytes',groups['toy-A'][0]['upload_bytes'],groups['toy-B'][0]['upload_bytes']],['Encrypted reply bytes',groups['toy-A'][0]['download_bytes'],groups['toy-B'][0]['download_bytes']],['Proof bytes','Not implemented','Not implemented'],['Tested correctness (trials)','10/10','10/10']], [240,132,132])
p('Ciphertext sizes above count a fixed-width, uncompressed serialization of two N-coefficient polynomial arrays modulo q, and omit key transmission and transport overhead. Query and reply counts are public-envelope dependent. “Proof bytes” is deliberately not zero: no zero-knowledge proof exists in this implementation, so proof size is not applicable.')
p('The plaintext baseline is much faster because it reveals the address-book values to the matching process and performs direct set operations. Comparing these local timings does not establish that a reviewed production HE library has similar overhead.')
page()
# Page 5
h('4. Threat model and leakage analysis')
p('In the intended semi-honest two-party model, the client should learn its contact matches without revealing client input values to the server. The educational prototype models server-side encrypted-polynomial evaluation as separate code paths in one process. Encryption and public transcript padding are present, but network-level isolation and a full security proof are not. Its tiny parameters cannot support a credible client-data confidentiality claim against a real attacker.')
h('Client and server observables')
p('The server logically sees the public hash seed, BFV-like public key, encrypted input powers, fixed bin count, field-part count, degree cap and the session workload. The client sees its own set, decrypted masked zero/nonzero field predicates, and the public envelope. Independent nonzero field masks hide the raw nonzero polynomial result in an ideal field calculation, but that alone does not show simulation security of the full implementation. Differences in local runtime and abort behavior are not protected against observation.')
h('False positives and integrity')
p('A zero for each of three field parts can arise from roots originating in different server items in the same bin, so a successful AND across parts does not prove one server item matched all parts. There is no established false-positive probability for these toy settings. Encryption does not guarantee server evaluation correctness: an active server can fabricate or alter ciphertexts, including causing false-zero outputs or decryption errors. A malicious client can submit values outside the intended phone-number domain; no proof binds ciphertext contents to normalized inputs.')
h('Unimplemented security controls')
p('The artifact includes no OPRF, input-consistency zero-knowledge proofs, server-evaluation proofs, authenticated registry commitments, TLS transport, abuse quotas, secure memory erasure or server authentication. Unkeyed phone-number hashing alone is dictionary-invertible and is never presented as a privacy solution. Repeated legitimate contact-discovery queries can enumerate registrations even if each individual query is encrypted.')
page()
# Page 6
h('5. Limitations and engineering next steps')
p('The most significant mismatch with Part 2 is architectural scale and cryptographic assurance. Part 2 specified N=8192/16384, 8192 bins, six field parts, m up to 4096, n from 2^16 to 2^22, and a validated HE 128-bit parameter chain. Here N=16/32, B=16/32, three field parts, a maximum of eight clients, and at most 24 server numbers were measured. These are intentional proof-of-concept restrictions, not evidence that larger targets have been met.')
h('Known technical restrictions')
table([['Component','Current state / required next work'],['Ring parameters','Toy N and ad hoc q; migrate to Microsoft SEAL or equivalent with tc128 context validation'],['Batching','No SIMD/CRT slots; implement native BFV batching and query-power generation'],['Server bins','Only one 8-root partition; implement multi-partition processing and fixed-count padded responses'],['Error probabilities','Three parts with root-mixing; analyze full-bundle false-positive probability and insertion failures'],['Noise budget','No invariant noise-budget measurement; evaluate circuit depth and actual SEAL noise margins'],['Active security','OPRF and ZK bindings, server-integrity proofs and authenticated transport are absent'],['Baselines','Measured plaintext baseline only; Microsoft APSI baseline unmeasured']], [130,378])
h('Practical extension sequence')
p('First replace homebuilt crypto with a maintained BFV implementation, verify N=8192 and 16384 parameter validity, and benchmark encrypted powers and evaluation circuits. Next implement correct partition-and-padding logic for every bin, add full-size field encodings and analytical collision accounting, and test m/n scaling with repeated runs, peak memory tracking and ciphertext/key serialization. Finally compare with Microsoft APSI, enforce authenticated session quotas, and explicitly define any malicious-party security properties before considering real contact data.')
page()
# Page 7
h('6. Reproducibility, rubric mapping, conclusion')
p('The archive is self-contained for Python 3.10+: `bash run.sh` executes the 16 unit tests and generates the 20 benchmark rows in `results/bfv_measurements.csv` and `results/bfv_measurements.json`. `README.md` records the algorithm, settings, expected output, byte accounting and all caveats. Measurements are intentionally regenerated on each run; individual latencies differ across systems. No GitHub URL is fabricated, and a public repository still must be created if the assignment requires a repository link.')
table([['Part 3 grading criterion','Direct evidence / remaining gap'],['Working reproducible implementation (20)','Runnable educational BFV-style code and run script; not full BFV/SEAL APSI'],['Evaluation rigor (15)','16 unit tests; 10 repeats per setting; measured time and ciphertext bytes; plaintext baseline'],['Limitations (10)','Explicit scope, missing security proof, root-mixing risk, overflow handling, absent APSI comparison'],['README and quality (5)','Documented source files, no external packages, exact run instructions and caveats']], [185,323])
h('Conclusion')
p('The delivered software shows that encrypted field-polynomial membership testing with padded binned queries can be implemented and tested end-to-end. It makes the privacy-preserving computation idea of Part 2 more concrete and provides executable correctness and measurement evidence for two toy configurations. However, the result is <b>not a completed, production-strength BFV/APSI realization of Part 2</b>, and its timing results do not validate the original large-scale performance budget. Any submission should accurately disclose this distinction.')
h('Sources / references')
p('[1] H. Chen, K. Laine and P. Rindal, “Fast Private Set Intersection from Homomorphic Encryption,” ACM CCS (2017).','Smallx')
p('[2] Microsoft Research, Microsoft SEAL, github.com/microsoft/SEAL (software reference).','Smallx')
p('[3] Microsoft Research, APSI: Asymmetric Private Set Intersection, github.com/microsoft/APSI (unmeasured reference baseline).','Smallx')
p('[4] Homomorphic Encryption Standard, homomorphicencryption.org (parameter-security reference).','Smallx')
p('[5] CYB 599 Graduate Project Part 2, Private Contact Discovery via Unbalanced PSI from Homomorphic Encryption, October 2026 (project design).','Smallx')

out=str(root/'evaluation_report_bfv.pdf')
def footer(canvas,doc):
 canvas.setFont('Helvetica',8);canvas.setFillColor(colors.HexColor('#566779'))
 canvas.drawString(45,36,'CYB 599 • BFV-style proof of concept • not cryptographically secure')
 canvas.drawRightString(570,36,f'Page {doc.page}')
SimpleDocTemplate(out,pagesize=(612,792),rightMargin=47,leftMargin=47,topMargin=44,bottomMargin=53,title='CYB 599 Part 3 BFV-Style Evaluation').build(story,onFirstPage=footer,onLaterPages=footer)
print(out)
