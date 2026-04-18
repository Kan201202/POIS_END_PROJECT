# CS8.401: Principles of Information Security — Programming Assignments

**Team:** Raj · Kanishk · Shubham · Shobhan · Swaraj  
**Language:** Python 3.11+ | **Tests:** pytest | **Frontend:** React + Flask  
**GitHub/Repo:** `/home/rajkjain/Downloads/POIS_PROJECT`

## 📖 Project Overview

This is a **complete implementation of the cryptographic reduction chain** from the *Minicrypt* and *Cryptomania* frameworks. We implement all 21 Programming Assignments (PA#0–PA#20) with **no external cryptographic libraries**, tracing every primitive back to its foundational assumptions.

### The Reduction Chain

```
Foundation Layer (OWF @ complexity ~2^128)
    ↓
    ├─ PA#1: OWF ⇔ PRG (HILL construction)
    ├─ PA#2: PRG ⇔ PRF (GGM tree)
    ├─ PA#4: PRF ⇔ PRP (Luby-Rackoff Feistel)
    └─ PA#5: PRF ⇔ MAC
        ├─ PA#3: PRF ⇒ CPA-Encryption
        ├─ PA#6: MAC ⇒ CCA-Encryption
        ├─ PA#7-10: Hash Functions & HMAC
        └─────────────────────────────────────┐
                                              ↓
Public-Key Layer (DLP/Factoring)         Minicrypt
    ├─ PA#11-12: DH & RSA
    ├─ PA#13: Miller-Rabin primality
    ├─ PA#14: CRT & Håstad broadcast
    ├─ PA#15: Digital Signatures
    ├─ PA#16: ElGamal
    └─ PA#17: CCA-Secure PKC
        ├─────────────────────────────────────┐
        ↓                                      │
Multi-Party Computation                  Cryptomania
    ├─ PA#18: Oblivious Transfer (OT)
    ├─ PA#19: Secure AND Gate
    └─ PA#20: All 2-Party Secure Computation (Yao/GMW)
                                              ↓
Interactive Web App (PA#0)             MPC Land
```

## 🎯 Team Assignments & Responsibilities

| Member | PAs | Role | Key Deliverables |
|--------|-----|------|-----------------|
| **Raj** | 1, 2, 13 | Cryptographic Foundations | OWF, PRG (HILL), PRF (GGM), Miller-Rabin |
| **Kanishk** | 3, 4, 6 | Symmetric Encryption | CPA-Enc, Modes (CBC/OFB/CTR), CCA-Enc |
| **Shubham** | 5, 7, 8, 9, 10 | MACs, Hashing, HMAC | CBC-MAC, Merkle-Damgård, DLP Hash, Birthday, HMAC |
| **Shobhan** | 11, 12, 14, 15, 16, 17 | Public-Key Crypto | DH, RSA, CRT, Signatures, ElGamal, PKC |
| **Swaraj** | 0, 18, 19, 20 | MPC & Web App | OT, Secure AND, Full 2-Party MPC, React UI |

## 📁 Project Structure

```
POIS_PROJECT/
├── README.md                           # This file
├── QUICKSTART.md                       # Getting started guide
├── RAJ_README.md                       # Raj's assignment details
├── requirements.txt                    # pytest + flask (only non-crypto deps!)
├── src/
│   ├── foundations/                    # PA#1: OWF, PRG
│   ├── prf/                           # PA#2: GGM PRF
│   ├── encry/                         # PA#3-6: Encryption (Kanishk)
│   ├── mac/                           # PA#5, #10: MACs (Shubham)
│   ├── hash/                          # PA#7-10: Hashing (Shubham)
│   ├── dh/                            # PA#11: DH (Shobhan)
│   ├── rsa/                           # PA#12, #14: RSA (Shobhan)
│   ├── sig/                           # PA#15: Signatures (Shobhan)
│   ├── elgamal/                       # PA#16: ElGamal (Shobhan)
│   ├── pke/                           # PA#17: CCA-PKC (Shobhan)
│   ├── mpc/                           # PA#18-20: MPC (Swaraj)
│   ├── primality/                     # PA#13: Miller-Rabin (Raj)
│   └── utils/                         # Shared utilities (Raj)
├── interfaces/                         # Abstract base classes (all)
├── tests/                             # pytest test files (each member)
├── web/                               # React app (Swaraj)
└── api/                               # Flask API bridge (Swaraj)
```

## 🚀 Getting Started

### 1. Clone/Set Up Workspace
```bash
cd /home/rajkjain/Downloads/POIS_PROJECT
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run Tests (Verify Setup)
```bash
# Run all tests
pytest tests/ -v

# Run specific member's tests (e.g., Raj)
pytest tests/test_pa1.py tests/test_pa2.py tests/test_pa13.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

### 4. Start Coding
- **Raj:** Begin with `src/primality/miller_rabin.py`
- **Kanishk:** Use Raj's PRF; start with `src/enc/cpa_enc.py`
- **Shubham:** Use PRF/hash; start with `src/mac/`
- **Shobhan:** Use Raj's prime gen; start with `src/dh/`
- **Swaraj:** Use Shobhan's PKC; start with `src/mpc/ot.py`

## ⚙️ Critical Rules

### 🚫 No External Crypto Libraries
- ❌ No `pycryptodome`, `cryptography`, `hashlib` (except os.urandom)
- ✅ ALLOWED: `os.urandom()`, Python built-in `int` (arbitrary precision)
- ✅ ALLOWED: pytest, flask (non-crypto utilities)

### ✅ Bidirectional Reductions (Marked with ✓)
Every bidirectional pair must implement BOTH directions:

| Pair | Forward | Backward |
|------|---------|----------|
| OWF ⇔ PRG | HILL construction | G(s) = built-in OWF |
| PRG ⇔ PRF | GGM tree | G(s) = F_s(0) ∥ F_s(1) |
| PRF ⇔ PRP | Luby-Rackoff 3-round Feistel | Switching lemma |
| PRF ⇔ MAC | MAC = F_k(m) | EUF-CMA implies PRF |
| CRHF ⇔ MAC | MAC compression + MD | MAC is collision-resistant |
| CRHF ⇔ HMAC | HMAC construction | HMAC keyed is CR hash |
| HMAC ⇔ MAC | HMAC directly | HMAC = MAC when secure |

### 📝 Full Reduction Chain in Code
Every reduction must be traceable in actual function calls:

```
PA#20 AND gate
  → PA#19 OT receiver step
      → PA#16 ElGamal Enc
          → PA#11 DH group gen
              → PA#13 Miller-Rabin
                  → square_and_multiply
                      → Python int ^
```

## 📅 8-Week Development Timeline

| Week | Milestone | Deliverables |
|------|-----------|--------------|
| **1** | Foundations + Interfaces | PA#1/2/13 (Raj), shared utils, interfaces |
| **2** | Symmetric crypto | PA#3-6 (Kanishk), PA#5/7-8 (Shubham) |
| **3** | Hashing + Modes | PA#4 (Kanishk), PA#9-10 (Shubham) |
| **4** | CCA-Enc + HMAC | PA#6 (Kanishk), PA#10 (Shubham) |
| **5** | Public-Key Crypto | PA#11-14 (Shobhan) |
| **6** | Signatures + PKC | PA#15-17 (Shobhan) |
| **7** | MPC Stack | PA#18-20 (Swaraj) |
| **8** | Integration + Web | PA#0 web app, all tests, README |

## 🧪 Testing Strategy

### Per-PA Test Files
Each PA has `tests/test_pa*.py`:
- Correctness: decrypt(encrypt(m)) = m, verify(mac(m)) = True
- Security games: IND-CPA, IND-CCA2, EUF-CMA (adversary advantage < 0.1)
- Attack demos: broken schemes fail when attacked
- Bidirectional: both A ⇒ B and B ⇒ A produce correct outputs

### Shared Integration Tests
- PRG statistical: NIST frequency/runs/serial tests
- Birthday empirical: 100 trials, ratio vs 2^(n/2) within 2×
- MPC lineage: PA#20 AND triggers PA#19 → PA#18 → PA#13

## 🎨 Web App (PA#0)

Interactive React interface showing the full reduction chain:

1. **Foundation Toggle:** AES vs DLP (concrete instantiation)
2. **Column 1:** Build source primitive from foundation
3. **Column 2:** Reduce source to target primitive
4. **Live Data Flow:** Real bytes flowing through each reduction step
5. **Proof Summary:** Theorem names, security reductions, PA numbers

Example path: AES (PRP) → PRF (switching lemma) → GGM PRF (GGM tree) → MAC

## 📚 Documentation

- **`RAJ_README.md`** — Detailed guide for Raj's assignments
- **`QUICKSTART.md`** — Getting started + test instructions
- **`src/*/` — Each module has docstrings with algorithm descriptions
- **Spec PDFs** — Attached: comprehensive PA specifications + math

## 🔗 Dependency Map

```
Raj's foundation (PA#1-2-13)
  ↓
  ├─→ Kanishk (PA#3: needs PRF)
  ├─→ Shubham (PA#5: needs PRF)
  └─→ Shobhan (PA#12: needs gen_prime)
      ├─→ Swaraj (PA#18: needs ElGamal)
      │   └─→ Swaraj (PA#19-20: needs OT)
      └─→ Kanishk (PA#6: needs RSA signatures)
```

## ✨ Key Features

- ✅ Full Minicrypt clique implemented (OWF ⇔ PRG ⇔ PRF ⇔ PRP ⇔ MAC)
- ✅ HMAC bridge to hashing (CRHF ⇔ MAC)
- ✅ Cryptomania (RSA, ElGamal, Digital Signatures)
- ✅ MPC (OT, Secure AND, full 2-party computation)
- ✅ No external crypto libraries — everything from scratch
- ✅ Bidirectional reductions proven in code
- ✅ Interactive web app with real data flow
- ✅ Comprehensive test suite (pytest)

## 📝 Submission Checklist

- [ ] All PAs implemented (PA#0-20)
- [ ] All bidirectional reductions (✓) implemented both ways
- [ ] All tests passing: `pytest tests/ -v`
- [ ] Code coverage ≥ 80%: `pytest --cov=src`
- [ ] No external crypto libraries used
- [ ] Full reduction chain traceable in code
- [ ] Web app functional with all PAs
- [ ] README + inline comments explain algorithm

## 🤝 Team Communication

- **Weekly code reviews:** Friday EOD each member shares interim work
- **Shared interfaces:** All code adheres to `interfaces/` abstract classes
- **Integration tests:** Run after each week to catch early issues
- **Deployment:** All tests must pass before final submission

## 📞 Support

- **PA Specs:** See attached PDF documents
- **Cryptography:** Course slides + referenced papers
- **Python:** See docstrings in each file
- **Integration:** Check other team members' code for usage patterns

---

**Status:** 🚀 Foundations and PKE layers (PAs 1, 2, 11, 12, 13, 14, 15, 16, 17) are 100% COMPLETE.

**Next:** Kanishk and Shubham complete their respective symmetric crypto and hashing tasks.

---

*Last updated: April 18, 2026*
