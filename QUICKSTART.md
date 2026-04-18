# POIS Project — Quick Start Guide (Raj + Shobhan)

## ✅ What's Been Set Up

### Raj's Implementations (PA#13, PA#1, PA#2)
1. **PA#13: Miller-Rabin Primality** → `src/primality/miller_rabin.py`
   - ✅ `is_prime(n, k)` — Miller-Rabin test with k rounds
   - ✅ `gen_prime(bits)` — Generate b-bit probable primes
   - ✅ `gen_prime_safe(bits)` — Generate safe primes p=2q+1
   - ✅ Tests in `tests/test_pa13.py`

2. **PA#1: OWF & PRG** → `src/foundations/owf.py`
   - ✅ `DLP_OWF` — Discrete Log based one-way function
   - ✅ `HILL_PRG` — Haastad-Impagliazzo-Levin-Luby generator
   - ✅ Goldreich-Levin hard-core predicate implementation
   - ✅ Tests in `tests/test_pa1.py`

3. **PA#2: GGM PRF** → `src/prf/ggm_prf.py`
   - ✅ `GGM_PRF` — Pseudorandom function via GGM tree
   - ✅ Binary tree traversal for PRF evaluation
   - ✅ Backward direction: PRG from PRF
   - ✅ Tests in `tests/test_pa2.py`

### Shobhan's Implementations (PA#11, PA#12, PA#14, PA#15, PA#16, PA#17)
4. **PA#11: Diffie-Hellman Key Exchange** → `src/dh/dh.py`
   - ✅ `generate_dh_params(bits)` — Safe prime group parameters
   - ✅ `dh_key_exchange(params)` — Full Alice-Bob key exchange
   - ✅ MITM attack demo (`Eve` class)
   - ✅ Tests in `tests/test_pa11.py`

5. **PA#12: RSA Encryption** → `src/rsa/rsa.py`
   - ✅ `rsa_keygen(bits)` — RSA key pair with CRT parameters
   - ✅ `rsa_enc / rsa_dec` — Textbook RSA
   - ✅ `pkcs15_enc / pkcs15_dec` — PKCS#1 v1.5 padded RSA
   - ✅ Bleichenbacher padding oracle demo
   - ✅ Tests in `tests/test_pa12.py`

6. **PA#14: CRT & Håstad Broadcast Attack** → `src/rsa/crt_rsa.py`
   - ✅ `crt(residues, moduli)` — General CRT solver
   - ✅ `rsa_dec_crt(sk, c)` — Garner's fast CRT decryption (~4× speedup)
   - ✅ `hastad_attack(...)` — Håstad's broadcast attack for small e
   - ✅ Tests in `tests/test_pa14.py`

7. **PA#15: Digital Signatures** → `src/sig/rsa_sig.py`
   - ✅ `sign(sk, m)` / `verify(pk, m, σ)` — Hash-then-sign RSA signatures
   - ✅ EUF-CMA security game
   - ✅ Multiplicative forgery demo (raw RSA without hash)
   - ✅ Tests in `tests/test_pa15.py`

8. **PA#16: ElGamal PKC** → `src/elgamal/elgamal.py`
   - ✅ `elgamal_keygen / elgamal_enc / elgamal_dec`
   - ✅ Malleability attack demo (CPA but NOT CCA)
   - ✅ Tests in `tests/test_pa16_pa17.py`

9. **PA#17: CCA-Secure PKC (Signcryption)** → `src/pke/signcrypt.py`
   - ✅ Encrypt-then-Sign: ElGamal + RSA signatures
   - ✅ `cca_pkc_enc / cca_pkc_dec` — Tamper-proof CCA wrapper
   - ✅ IND-CCA2 game demo
   - ✅ Tests in `tests/test_pa16_pa17.py`

### Shared Utilities
- ✅ `src/utils/random_utils.py` — `generate(n)` using os.urandom
- ✅ `src/utils/mod_exp.py` — `square_and_multiply(base, exp, mod)`
- ✅ `src/utils/ext_gcd.py` — Extended GCD and modular inverse
- ✅ `src/utils/int_root.py` — Integer root computation

### Interfaces (Shared with Team)
- ✅ `src/interfaces/owf.py` — OWF abstract base class
- ✅ `src/interfaces/prg.py` — PRG abstract base class
- ✅ `src/interfaces/prf.py` — PRF abstract base class

---

## 🚀 Getting Started

### 1. Set Up Python Environment
```bash
cd /home/lparida/Desktop/POIS_Proj/POIS_PROJECT
pip install -r requirements.txt   # installs pytest
```

### 2. Run All Tests (Complete Suite)
```bash
# Run ALL tests from both Raj and Shobhan
pytest tests/ -v

# Or run all test files explicitly
pytest tests/test_pa13.py tests/test_pa1.py tests/test_pa2.py \
       tests/test_pa11.py tests/test_pa12.py tests/test_pa14.py \
       tests/test_pa15.py tests/test_pa16_pa17.py -v
```

### 3. Run Tests by PA

#### Raj's Tests
```bash
pytest tests/test_pa13.py -v   # PA#13 — Miller-Rabin primality
pytest tests/test_pa1.py  -v   # PA#1  — OWF & PRG
pytest tests/test_pa2.py  -v   # PA#2  — GGM PRF
```

#### Shobhan's Tests
```bash
pytest tests/test_pa11.py      -v   # PA#11  — Diffie-Hellman
pytest tests/test_pa12.py      -v   # PA#12  — Textbook RSA + PKCS#1 v1.5
pytest tests/test_pa14.py      -v   # PA#14  — CRT + Håstad attack
pytest tests/test_pa15.py      -v   # PA#15  — Digital Signatures
pytest tests/test_pa16_pa17.py -v   # PA#16/17 — ElGamal + CCA Signcrypt
```

> ⚠️ **Note:** Tests that generate large primes (PA#1, PA#2, PA#11, PA#12) may take 30–120 seconds each — this is expected.

---

## 📋 Project Status

| PA | Topic | Author | Source | Tests | Status |
|----|-------|--------|--------|-------|--------|
| PA#13 | Miller-Rabin Primality | Raj | `src/primality/miller_rabin.py` | `test_pa13.py` | ✅ |
| PA#1  | OWF & PRG | Raj | `src/foundations/owf.py` | `test_pa1.py` | ✅ |
| PA#2  | GGM PRF | Raj | `src/prf/ggm_prf.py` | `test_pa2.py` | ✅ |
| PA#11 | Diffie-Hellman | Shobhan | `src/dh/dh.py` | `test_pa11.py` | ✅ |
| PA#12 | RSA Encryption | Shobhan | `src/rsa/rsa.py` | `test_pa12.py` | ✅ |
| PA#14 | CRT & Håstad Attack | Shobhan | `src/rsa/crt_rsa.py` | `test_pa14.py` | ✅ |
| PA#15 | Digital Signatures | Shobhan | `src/sig/rsa_sig.py` | `test_pa15.py` | ✅ |
| PA#16 | ElGamal PKC | Shobhan | `src/elgamal/elgamal.py` | `test_pa16_pa17.py` | ✅ |
| PA#17 | CCA Signcryption | Shobhan | `src/pke/signcrypt.py` | `test_pa16_pa17.py` | ✅ |
| Shared Utils | Utilities | Raj | `src/utils/` | — | ✅ |
| Interfaces | ABC classes | Raj | `src/interfaces/` | — | ✅ |

---

## 📁 Full Project Layout

```
POIS_PROJECT/
├── conftest.py                         # pytest path setup (auto-loaded)
├── requirements.txt                    # pytest only
│
├── src/
│   ├── __init__.py
│   ├── interfaces/
│   │   ├── owf.py                      # OWF abstract base class
│   │   ├── prg.py                      # PRG abstract base class
│   │   └── prf.py                      # PRF abstract base class
│   ├── utils/
│   │   ├── random_utils.py             # os.urandom wrapper
│   │   ├── mod_exp.py                  # Square-and-multiply
│   │   ├── ext_gcd.py                  # Extended GCD + mod inverse
│   │   └── int_root.py                 # Integer e-th root
│   ├── primality/
│   │   └── miller_rabin.py             # PA#13: Primality
│   ├── foundations/
│   │   └── owf.py                      # PA#1:  OWF & PRG
│   ├── prf/
│   │   └── ggm_prf.py                  # PA#2:  GGM PRF
│   ├── dh/
│   │   └── dh.py                       # PA#11: Diffie-Hellman
│   ├── rsa/
│   │   ├── rsa.py                      # PA#12: RSA + PKCS#1 v1.5
│   │   └── crt_rsa.py                  # PA#14: CRT + Håstad
│   ├── sig/
│   │   └── rsa_sig.py                  # PA#15: Digital Signatures
│   ├── elgamal/
│   │   └── elgamal.py                  # PA#16: ElGamal PKC
│   └── pke/
│       └── signcrypt.py                # PA#17: CCA Signcryption
│
└── tests/
    ├── test_pa13.py                    # PA#13 tests (Raj)
    ├── test_pa1.py                     # PA#1  tests (Raj)
    ├── test_pa2.py                     # PA#2  tests (Raj)
    ├── test_pa11.py                    # PA#11 tests (Shobhan)
    ├── test_pa12.py                    # PA#12 tests (Shobhan)
    ├── test_pa14.py                    # PA#14 tests (Shobhan)
    ├── test_pa15.py                    # PA#15 tests (Shobhan)
    └── test_pa16_pa17.py               # PA#16+17 tests (Shobhan)
```

---

## ⚠️ Important Notes

1. **No External Crypto:** All code uses only `os.urandom` + Python `int`
2. **Bidirectional Reductions:** Both directions of each reduction are implemented
3. **Safe Primes:** Always use `gen_prime_safe()` for DH/DLP protocols
4. **Run from project root:** All pytest commands should be run from `POIS_PROJECT/`
5. **Slow tests are expected:** Prime generation for 128-bit+ primes takes time

---

**See `RAJ_README.md` and `SHOBHAN_README.md` for per-author implementation details.** 🚀
