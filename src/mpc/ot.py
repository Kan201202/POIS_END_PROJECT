"""
PA#18: 1-of-2 Oblivious Transfer (Bellare-Micali style)
Uses Shobhan's ElGamal functions from src/elgamal/elgamal.py
"""
from src.elgamal.elgamal import elgamal_keygen, elgamal_enc, elgamal_dec
from src.utils.random_utils import generate


class OT:
    def receiver_step1(self, choice_bit: int):
        # Real keypair for chosen index
        pk_real, sk_real = elgamal_keygen(bits=256)
        p, q, g = pk_real["p"], pk_real["q"], pk_real["g"]

        # Fake pk — random group element, no secret key known
        rand_exp = int.from_bytes(generate(32), 'big') % q
        fake_h = pow(g, rand_exp, p)
        fake_pk = {"p": p, "q": q, "g": g, "h": fake_h}

        if choice_bit == 0:
            pk0, pk1 = pk_real, fake_pk
        else:
            pk0, pk1 = fake_pk, pk_real

        state = (choice_bit, sk_real)
        return pk0, pk1, state

    def sender_step(self, pk0, pk1, m0: bytes, m1: bytes):
        c0 = elgamal_enc(pk0, int.from_bytes(m0, 'big') % pk0["p"])
        c1 = elgamal_enc(pk1, int.from_bytes(m1, 'big') % pk1["p"])
        return c0, c1

    def receiver_step2(self, state, c0, c1) -> bytes:
        choice_bit, sk_real = state
        c = c0 if choice_bit == 0 else c1
        m_int = elgamal_dec(sk_real, c[0], c[1])
        return m_int.to_bytes(16, 'big')