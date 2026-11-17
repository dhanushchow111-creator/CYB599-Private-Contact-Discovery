# CYB 599 Part 3 — BFV-style Binned Private Contact Discovery (Educational Implementation)

**Important scope statement:** This project is a working, dependency-free **toy ring-BFV-style encrypted polynomial-membership demonstrator** implementing a small subset of the Part 2 design, not a production BFV library, Microsoft SEAL, Microsoft APSI, or a cryptographically secure contact-discovery service. The configuration uses **N=16 or 32**, not Part 2's N=8192/16384. It has **no validated classical security level**. Never use this code with real personal information.

## Reproduce from a clean environment

Requires Python **3.10+** on macOS, Linux, or Windows (PowerShell commands below). All input numbers are synthetic. No `pip install`, network connection, GPU or external library is needed.

```bash
unzip cyb599_bfv_part3.zip
cd cyb599_bfv_part3
bash run.sh
```

Alternatively, including on Windows:

```bash
python3 -m unittest discover -s tests -v
python3 benchmark.py --repetitions 10 --output results
```

On Windows use `py -3` in place of `python3`. If you already extracted the folder, do not run unzip again. Benchmarks overwrite `results/bfv_measurements.csv` and `.json` with machine-local measurements. Expected outputs: **16 passing unit tests**, 10 repetitions for each of the two toy settings, plus a recorded plaintext baseline.

## What actually works

- Validate, canonicalize, deduplicate synthetic E.164 numbers.
- Encode each phone number as **three independent domain-separated field parts** modulo t=65537.
- Place the client set in **public-seed three-choice cuckoo bins**, pad every other bin with independently random dummy field values; the server inserts each item in all candidate bins, and rejects overfull bins (does not silently discard entries).
- Encrypt powers z^1 through z^8 with a self-contained **ring-LWE/BFV-style public-key implementation**, using polynomials modulo X^N+1 and q=2^120-17. Supports encryption, decryption, homomorphic addition and plaintext scalar multiplication, **not ciphertext multiplication, relinearization, rotation, or SIMD batching**.
- Evaluate per-part membership polynomials `P(Z)=prod(Z-root)` as ciphertext-linear combinations of the encrypted powers, using centered plaintext coefficients and an independent random nonzero field mask on each returned part.
- Client decrypts and accepts a bin item only if all three field parts yield zero for the same bin response; reconstructs only real placed contacts.
- Pad *all* query and response ciphertext counts using a publicly bounded envelope and single server-bin partition; fail on overflow.
- Validate end-to-end intersections against direct plaintext set intersection; benchmark generation/encryption, server evaluation, recovery, and bytes on two toy settings.

## Experimental settings

| Setting | N | q | t | B | Max client | Max server | Parts | Degree cap |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| toy-A | 16 | 2^120 - 17 | 65537 | 16 | 4 | 12 | 3 | 8 |
| toy-B | 32 | 2^120 - 17 | 65537 | 32 | 8 | 24 | 3 | 8 |

**Neither is a secure BFV parameter set.** The sizes and benchmarked data are NOT representative of the Part 2 128-bit target. Query ciphertexts are `B × parts × degree_cap` and responses `B × parts`. Encoded ciphertext size is the **uncompressed fixed-width representation of two polynomials**, each of N q-residue coefficients. Proof size is **not applicable** (no ZK proof is implemented).

## Files

- `src/bfv_demo.py` — self-contained toy ring encryption, cuckoo bins, finite-field encoding, masked polynomial evaluations, tests and baseline functions.
- `tests/test_bfv.py` — 16 tests for correctness, encrypted operations, validation, envelope boundaries, fixed message counts, and two settings.
- `benchmark.py` — deterministic synthetic workload, 10 timed trials / parameter set and plaintext baseline, correctness assertion, raw CSV/JSON export.
- `run.sh` — runs all tests then benchmarks; no installation needed.
- `results/bfv_measurements.csv` and `.json` — saved actual measurements in the execution environment. They change on rerun.
- `evaluation_report_bfv.pdf` — seven-page report describing methodology, measured results and limitations.

## Security and missing components

This is *research/teaching code*. The security claim **is not 128-bit** and cannot be made for this homebuilt algorithm. The q choice is not reviewed or validated by SEAL; N is far too small. There is no SIMD batching, OPRF, oblivious transfer, malicious-party security, server-authentication, TLS network protocol, proof of input consistency, proof of server evaluation, advanced query-power schedule, persistent registration service, multi-partition overflow processing, noise-budget instrumentation, or full-scale APSI measurements. Although the result reveals the match predicate to the client in an honest execution, **this is not a formal PSI security proof**. The three field-part polynomial zero checks are vulnerable to root-mixing false positives under pathological inputs and are not proven to meet Part 2's 2^-40 total false-positive target. The implementation cannot serve as a safe substitute for a reviewed HE library.

Part 2 proposed N=8192/16384, B=8192, m<=4096, n>=65536, six field parts, a degree cap 32 and up, and library-validated parameter chains. **None of these original large-scale secure targets was executed here**. Comparisons in the PDF use a truly non-private plaintext set-intersection baseline, NOT a measured Microsoft APSI implementation. No proof sizes are fabricated.

## Repository

The repository URL must be supplied by the student after publishing the reviewed archive on an authorized git hosting provider. This archive does not contain an invented GitHub link. Ensure the instructor permits this educational prototype in lieu of the originally specified production-library BFV/SEAL plan.
