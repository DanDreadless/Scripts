#The aliens have learned of a new concept called "security by obscurity".
#Fortunately for us they think it is a great idea and not a description 
#of a common mistake. We've intercepted some alien comms and think they
#are XORing flags with a single-byte key and hiding the result inside 9999
#lines of random data, Can you find the flag?

flag_start = b'CHTB{'

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

with open('output.txt', 'r') as f:
    ciphertext = f.read()
    ciphertext = ciphertext.replace("\n", "").strip()
    ciphertext = bytes.fromhex(ciphertext)

for b in range(0,256):
    key = bytes((b for i in range(0,len(ciphertext))))
    plaintext = byte_xor(ciphertext, key)
    if flag_start in plaintext:
        index = plaintext.index(flag_start)
        print(plaintext[index:(index+100)])
