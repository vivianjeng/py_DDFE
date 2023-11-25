"""
Test DSum class
"""
import random
from py_ecc import (
    optimized_bn128 as bn128,
)
from dsum import DSum


def test_main():
    """
    Test DSum class
    """
    user_num = 5
    pk = []
    sk = []
    r = [random.randint(0, bn128.field_modulus) for i in range(user_num)]
    x = [random.randint(0, bn128.field_modulus) for i in range(user_num)]

    k_pk = []
    r_pk_2 = []
    s_pk = []
    dsum = DSum()

    # Key generation
    for i in range(user_num):
        tmp_pk, tmp_sk = dsum.keygen()
        pk.append(tmp_pk)
        sk.append(tmp_sk)

    # All users encrypt data
    c_pks = []
    for i in range(user_num):
        k, c_pk, r2, s, l = dsum.encrypt(
            sk[i], r[i], x[i], pk[:i]+pk[i+1:], 12345)
        k_pk.append(k)
        r_pk_2.append(r2)
        s_pk.append(s)
        c_pks.append(c_pk)

    # Decrypt each ciphertext
    for i in range(user_num):
        assert dsum.decrypt(r[i], s_pk[:i]+s_pk[i+1:]) == k_pk[i]
        assert (sum(x) == sum(c_pks))

    print("Test Finish!")
