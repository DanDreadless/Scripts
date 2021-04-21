#The aliens are trying to build a secure cipher to encrypt all our games called "PhaseStream".
#They've heard that stream ciphers are pretty good.
#The aliens have learned of the XOR operation which is used to encrypt a plaintext with a key.
#They believe that XOR using a repeated 5-byte key is enough to build a strong stream cipher.
#Such silly aliens! Here's a flag they encrypted this way earlier.
#Can you decrypt it (hint: what's the flag format?)
#2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


ciphertext = bytes.fromhex('2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904')
flagformat = 'CHTB{fLaG_fOrMaT}'.encode()
key = byte_xor(flagformat[0:5], ciphertext[0:5])
print('Key seems to be:', key)

keystream = (key * 10)[0:len(ciphertext)] # horrible but I have 5 mins left lol
plaintext = byte_xor(ciphertext, keystream)
print('Plaintext is:', plaintext)
