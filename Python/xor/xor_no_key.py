#The aliens saw us break PhaseStream 3 and have proposed a quick fix to protect their new cipher.

def byte_xor(ba1, ba2):
    if len(ba1) != len(ba2):
        raise ValueError('bytearray lengths mismatch')
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

ciphertext_test = bytes.fromhex('6b65813f4fe991efe2042f79988a3b2f2559d358e55f2fa373e53b1965b5bb2b175cf039')
ciphertext_flag = bytes.fromhex('fd034c32294bfa6ab44a28892e75c4f24d8e71b41cfb9a81a634b90e6238443a813a3d34')

test_xor_flag = byte_xor(ciphertext_test[0:len(ciphertext_flag)], ciphertext_flag)

flag_start = b'HTB{'

test_start = byte_xor(test_xor_flag[0:len(flag_start)], flag_start)

print(test_start)
# 'I alo' might be 'I alone'. This is a famous quote that starts with that
quote_candidate = b'I alone cannot change the world, but I can cast a stone across the water to create many ripples'

flag = byte_xor(quote_candidate[0:len(ciphertext_flag)], test_xor_flag)
print(flag)
