"""
Test AoNE class
"""
import random
from py_ecc import (
    optimized_bn128 as bn128,
)
from aone import AoNE


def test_main():
    """
    Test AoNE class
    """
    user_num = 5
    pk = []
    sk = []
    r = [random.randint(0, bn128.field_modulus) for i in range(user_num)]
    x = [random.randint(0, bn128.field_modulus) for i in range(user_num)]
    k_pk = []
    r_pk_2 = []
    s_pk = []
    aone = AoNE()

    # Key generation
    for i in range(user_num):
        tmp_pk, tmp_sk = aone.keygen()
        pk.append(tmp_pk)
        sk.append(tmp_sk)

    # All users encrypt data
    for i in range(user_num):
        k, m, r2, s, l = aone.encrypt(sk[i], r[i], x[i], pk[:i]+pk[i+1:], 12345)
        k_pk.append(k)
        r_pk_2.append(r2)
        s_pk.append(s)

    # Decrypt each ciphertext
    for i in range(user_num):
        assert aone.decrypt(r[i], s_pk[:i]+s_pk[i+1:]) == k_pk[i]

    print("Test Finish!")
