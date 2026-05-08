# CS8.401 — Principles of Information Security
## Team: Raj · Kanishk · Shubham · Shobhan · Swaraj

---

## Quick Setup

```bash
# Install dependencies
pip install pytest flask flask-cors

# Make sure you are inside the project folder
cd POIS_PROJECT
```

---

## Run All Tests

```bash
pytest tests/ -v
```

Expected: **126 passed**

---

## Run Tests by Person

```bash
# Raj — PA#1, PA#2, PA#13
pytest tests/test_pa1.py tests/test_pa2.py tests/test_pa13.py tests/test_pa1_nist.py -v

# Kanishk — PA#3, PA#4, PA#6
pytest tests/test_pa3_pa4_pa6.py -v

# Shubham — PA#5, PA#7, PA#8, PA#9, PA#10
pytest tests/test_pa5.py tests/test_pa7.py tests/test_pa8.py tests/test_pa9.py tests/test_pa10.py -v

# Shobhan — PA#11 to PA#17
pytest tests/test_pa11.py tests/test_pa12.py tests/test_pa14.py tests/test_pa15.py tests/test_pa16_pa17.py -v

# Swaraj — PA#18, PA#19, PA#20
pytest tests/test_pa18_pa19_pa20.py -v
```

---

## Run the Web App

You need **two terminals open at the same time**.

**Terminal 1 — Start Flask API (Python backend):**
```bash
cd POIS_PROJECT
python api/app.py
```
Keep this running. You should see:
```
Running on http://127.0.0.1:5000
```

**Terminal 2 — Start React frontend:**
```bash
cd POIS_PROJECT/web
npm install
npm run dev
```

Then open your browser at:
```
http://localhost:5173
```

---

## Project Structure

```
POIS_PROJECT/
├── src/
│   ├── foundations/     Raj     — OWF, PRG (PA#1)
│   ├── prf/             Raj     — GGM PRF (PA#2)
│   ├── primality/       Raj     — Miller-Rabin (PA#13)
│   ├── utils/           Raj     — Shared utilities
│   ├── enc/             Kanishk — CPA-Enc, Modes, CCA-Enc (PA#3,4,6)
│   ├── mac/             Shubham — MACs, HMAC (PA#5,10)
│   ├── hash/            Shubham — Merkle-Damgard, DLP Hash (PA#7,8)
│   ├── attack/          Shubham — Birthday attack (PA#9)
│   ├── dh/              Shobhan — Diffie-Hellman (PA#11)
│   ├── rsa/             Shobhan — RSA, CRT (PA#12,14)
│   ├── sig/             Shobhan — Signatures (PA#15)
│   ├── elgamal/         Shobhan — ElGamal (PA#16)
│   ├── pke/             Shobhan — CCA-PKC (PA#17)
│   └── mpc/             Swaraj  — OT, AND gate, MPC (PA#18,19,20)
├── tests/               All test files
├── api/                 Swaraj  — Flask API bridge for web app
├── web/                 Swaraj  — React frontend (PA#0)
└── interfaces/          Abstract base classes for all primitives
```

---

## Common Issues

**pytest not found:**
```bash
pip install pytest
```

**Flask API error / cannot reach API:**
- Make sure `python api/app.py` is running in a separate terminal
- Check it says `Running on http://127.0.0.1:5000`

**npm not found:**
- Install Node.js from https://nodejs.org

**Tests are slow:**
- This is normal — GGM PRF and OT use real crypto (DLP, Miller-Rabin)
- Full suite takes ~30 minutes
- Run individual PA tests to check specific parts quickly

**Merge conflict in miller_rabin.py:**
- Open the file, delete all lines with `<<<<<<<`, `=======`, `>>>>>>>`
- Keep only the bottom version of the conflicting block

---

## Key Rules (from assignment spec)

- No external crypto libraries — no pycryptodome, hashlib, cryptography etc.
- Only `os.urandom` and Python built-in `int` are allowed
- Every PA must trace its dependency chain back to your own implementations
- Bidirectional reductions marked in the spec must implement BOTH directions