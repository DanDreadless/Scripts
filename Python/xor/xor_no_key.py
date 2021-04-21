#The aliens saw us break PhaseStream 3 and have proposed a quick fix to protect their new cipher.

def byte_xor(ba1, ba2):
    if len(ba1) != len(ba2):
        raise ValueError('bytearray lengths mismatch')
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

ciphertext_test = bytes.fromhex('2d0fb3a56aa66e1e44cffc97f3a2e030feab144124e73c76d5d22f6ce01c46e73a50b0edc1a2bd243f9578b745438b00720870e3118194cbb438149e3cc9c0844d640ecdb1e71754c24bf43bf3fd0f9719f74c7179b6816e687fa576abad1955')
ciphertext_flag = bytes.fromhex('2767868b7ebb7f4c42cfffa6ffbfb03bf3b8097936ae3c76ef803d76e11546947157bcea9599f826338807b55655a05666446df20c8e9387b004129e10d18e9f526f71cabcf21b48965ae36fcfee1e820cf1076f65')

test_xor_flag = byte_xor(ciphertext_test[0:len(ciphertext_flag)], ciphertext_flag)

flag_start = b'CHTB{'

test_start = byte_xor(test_xor_flag[0:len(flag_start)], flag_start)

print(test_start)
# 'I alo' might be 'I alone'. This is a famous quote that starts with that
quote_candidate = b'I alone cannot change the world, but I can cast a stone across the water to create many ripples'

flag = byte_xor(quote_candidate[0:len(ciphertext_flag)], test_xor_flag)
print(flag)
