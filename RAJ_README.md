# POIS Project — Integrated Team Assignment

**Students:** Raj & Shobhan  
**Raj's Role:** Cryptographic Foundations (OWF, PRG, PRF, Primality)  
**Shobhan's Role:** Public-Key Cryptography (DH, RSA, ElGamal, Sig, CCA-PKC)  

---

## Overview

This repository contains the integrated cryptographic library for the POIS project. The project follows a strict reduction-based structure:

```
PA#13 (Miller-Rabin) → PA#1 (OWF, PRG) → PA#2 (PRF/GGM Tree) → PA#11-17 (Shobhan's PKE chain)
```

Both authors have contributed to a unified project structure where foundations and higher-level primitives work together seamlessly.

---

## 👨‍💻 Raj's Contribution (Foundations)

### Shared Utilities & Interfaces
- ✅ **`src/utils/`** — `random_utils`, `mod_exp`, `ext_gcd`, `int_root`.
- ✅ **`src/interfaces/`** — Abstract classes for OWF, PRG, and PRF.

### PA#13: Miller-Rabin Primality Testing
- **File:** `src/primality/miller_rabin.py`
- **Key Functions:** `is_prime(n, k)`, `gen_prime(bits)`, `gen_prime_safe(bits)`.
- **Note:** Provides the prime generation engine used by RSA and Diffie-Hellman.

### PA#1: One-Way Functions & Pseudorandom Generators
- **File:** `src/foundations/owf.py`
- **Implementations:** `DLP_OWF` (Discrete Log), `FactorOWF` (Factoring), `HILL_PRG` (HILL construction).
- **Reductions:** Forward (OWF ⇒ PRG) and Backward (PRG ⇒ OWF).

### PA#2: GGM Pseudorandom Function
- **File:** `src/prf/ggm_prf.py`
- **Implementations:** `GGM_PRF` (Binary tree construction), `PRG_from_PRF` (Backward reduction).
- **Features:** GGM tree traversal and IND-PRF distinguishing game.

---

## 👨‍💻 Shobhan's Contribution (Public-Key Cryptography)

### PA#11: Diffie-Hellman Key Exchange
- **File:** `src/dh/dh.py`
- **Features:** Safe-prime group generation, Alice/Bob protocol steps, and Active MITM attack demo.
- **Robustness:** Includes `_gen_prime_robust` to handle cryptographic edge cases in random bit generation.

### PA#12: RSA Encryption (Textbook & PKCS#1 v1.5)
- **File:** `src/rsa/rsa.py`
- **Features:** Keygen with CRT parameters, Textbook RSA (deterministic), and randomized PKCS#1 v1.5 padding.
- **Security Demo:** `determinism_attack_demo` and simplified `bleichenbacher_simplified` padding oracle.

### PA#14: CRT & Håstad Broadcast Attack
- **File:** `src/rsa/crt_rsa.py`
- **Features:** General CRT solver, Garner's Algorithm (4x faster RSA decryption), and Håstad's broadcast attack for small exponent $e=3$.

### PA#15: Digital Signatures
- **File:** `src/sig/rsa_sig.py`
- **Features:** RSA hash-then-sign signatures, EUF-CMA security game, and multiplicative forgery demo for unhashed RSA.

### PA#16: ElGamal Public-Key Cryptosystem
- **File:** `src/elgamal/elgamal.py`
- **Features:** Cyclic group encryption (CPA-secure) and malleability demo showing ElGamal is NOT CCA-secure.

### PA#17: CCA-Secure PKC (Signcryption)
- **File:** `src/pke/signcrypt.py`
- **Features:** Encrypt-then-Sign construction using ElGamal and RSA signatures.
- **Security:** Blocks malleability attacks (IND-CCA2 secure).

---

## 🚀 Running the Project Suite

```bash
# Install dependencies (pytest)
pip install -r requirements.txt

# Run ALL 62 test cases from both authors
pytest tests/ -v
```

### Individual Author Tests
```bash
# Raj's Tests (Foundations)
pytest tests/test_pa1.py tests/test_pa2.py tests/test_pa13.py -v

# Shobhan's Tests (PKE)
pytest tests/test_pa11.py tests/test_pa12.py tests/test_pa14.py \
       tests/test_pa15.py tests/test_pa16_pa17.py -v
```

---

## 📂 Project Structure

```
POIS_PROJECT/
├── conftest.py                # Auto-injects src/ into sys.path
├── RAJ_README.md              # This integrated README
├── SHOBHAN_README.md          # Original Shobhan documentation
├── src/
│   ├── foundations/           # Raj: PA#1
│   ├── prf/                   # Raj: PA#2
│   ├── primality/             # Raj: PA#13
│   ├── dh/                    # Shobhan: PA#11
│   ├── rsa/                   # Shobhan: PA#12, PA#14
│   ├── sig/                   # Shobhan: PA#15
│   ├── elgamal/               # Shobhan: PA#16
│   └── pke/                   # Shobhan: PA#17
└── tests/                     # 62 Test cases across all 9 PAs
```

---

## 📋 Comprehensive PA Checklist

| PA | Author | Description | Status |
|----|--------|-------------|--------|
| PA#13 | Raj | Miller-Rabin & Prime Gen | ✅ |
| PA#1 | Raj | OWF & PRG (HILL) | ✅ |
| PA#2 | Raj | GGM PRF Tree | ✅ |
| PA#11 | Shobhan | Diffie-Hellman & MITM | ✅ |
| PA#12 | Shobhan | RSA & PKCS#1 v1.5 | ✅ |
| PA#14 | Shobhan | CRT & Håstad Attack | ✅ |
| PA#15 | Shobhan | Digital Signatures | ✅ |
| PA#16 | Shobhan | ElGamal PKC | ✅ |
| PA#17 | Shobhan | CCA Signcryption | ✅ |

---

## ⚠️ Important Notes

1. **Integrated Robustness:** Shobhan's modules use a robust prime generation wrapper to ensure stable execution during large-bit key generation.
2. **Performance:** Garner's CRT decryption (PA#14) provides significant speedup over standard RSA.
3. **Security:** All constructions (Signatures, CCA-PKC) are verified via formal security games (EUF-CMA, IND-CCA2) in the test suite.
