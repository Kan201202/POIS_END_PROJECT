// Central registry of all PA tasks. Imported by App.jsx for sidebar + routing.
import PA0 from "./PA0";
import PA1 from "./PA1";
import PA2 from "./PA2";
import PA3 from "./PA3";
import PA4 from "./PA4";
import PA5 from "./PA5";
import PA6 from "./PA6";
import PA7 from "./PA7";
import PA8 from "./PA8";
import PA9 from "./PA9";
import PA10 from "./PA10";
import PA11 from "./PA11";
import PA12 from "./PA12";
import PA13 from "./PA13";
import PA14 from "./PA14";
import PA15 from "./PA15";
import PA16 from "./PA16";
import PA17 from "./PA17";
import PA18 from "./PA18";
import PA19 from "./PA19";
import PA20 from "./PA20";

export const TASKS = [
  // Group: Minicrypt foundations
  { id: "pa0",  num: "00", section: "Overview",      name: "Clique Explorer",     short: "Cross-primitive reductions", component: PA0 },
  { id: "pa1",  num: "01", section: "Minicrypt",     name: "OWF + PRG",           short: "DLP one-way function & HILL PRG", component: PA1 },
  { id: "pa2",  num: "02", section: "Minicrypt",     name: "PRF (GGM tree)",      short: "Pseudorandom function from PRG", component: PA2 },
  { id: "pa3",  num: "03", section: "Minicrypt",     name: "CPA Encryption",      short: "Symmetric encryption with PRF",  component: PA3 },
  { id: "pa4",  num: "04", section: "Minicrypt",     name: "Modes (CBC/OFB/CTR)", short: "Block-cipher modes of operation", component: PA4 },
  { id: "pa5",  num: "05", section: "Minicrypt",     name: "MAC",                 short: "PRF-MAC and CBC-MAC",            component: PA5 },
  { id: "pa6",  num: "06", section: "Minicrypt",     name: "CCA Encryption",      short: "Encrypt-then-MAC",                component: PA6 },

  // Group: Hashing
  { id: "pa7",  num: "07", section: "Hashing",       name: "Merkle–Damgård",      short: "Domain extension transform",     component: PA7 },
  { id: "pa8",  num: "08", section: "Hashing",       name: "DLP Hash (CRHF)",     short: "Collision-resistant hash from DLP", component: PA8 },
  { id: "pa9",  num: "09", section: "Hashing",       name: "Birthday Attack",     short: "Empirical √N collision finder",  component: PA9 },
  { id: "pa10", num: "10", section: "Hashing",       name: "HMAC + EtH",          short: "HMAC and Encrypt-then-HMAC",      component: PA10 },

  // Group: Public-key
  { id: "pa11", num: "11", section: "Public-Key",    name: "Diffie-Hellman",      short: "Shared-key exchange",            component: PA11 },
  { id: "pa12", num: "12", section: "Public-Key",    name: "RSA",                 short: "Textbook + PKCS#1 v1.5",          component: PA12 },
  { id: "pa13", num: "13", section: "Public-Key",    name: "Miller-Rabin",        short: "Probabilistic primality test",   component: PA13 },
  { id: "pa14", num: "14", section: "Public-Key",    name: "CRT + Håstad",        short: "Broadcast attack on small-e RSA", component: PA14 },
  { id: "pa15", num: "15", section: "Public-Key",    name: "Digital Signatures",  short: "Hash-then-sign RSA",             component: PA15 },
  { id: "pa16", num: "16", section: "Public-Key",    name: "ElGamal",             short: "DLP-based PKE",                  component: PA16 },
  { id: "pa17", num: "17", section: "Public-Key",    name: "CCA-Secure PKC",      short: "Sign-then-encrypt",              component: PA17 },

  // Group: MPC
  { id: "pa18", num: "18", section: "MPC",           name: "Oblivious Transfer",  short: "1-of-2 OT from PKE",             component: PA18 },
  { id: "pa19", num: "19", section: "MPC",           name: "Secure Gates",        short: "AND / XOR / NOT over shares",    component: PA19 },
  { id: "pa20", num: "20", section: "MPC",           name: "2-Party MPC",         short: "Millionaires, equality, sum",    component: PA20 },
];

export const TASK_BY_ID = Object.fromEntries(TASKS.map(t => [t.id, t]));
