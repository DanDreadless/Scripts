#The aliens have learned the stupidity of their misunderstanding of Kerckhoffs's principle.
#Now they're going to use a well-known stream cipher (AES in CTR mode) with a strong key.
#And they'll happily give us poor humans the source because they're so confident it's secure!

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

test_message = b"No right of private conversation was enumerated in the Constitution. I don't suppose it occurred to anyone at the time that it could be prevented."

ciphertext_test = bytes.fromhex('464851522838603926f4422a4ca6d81b02f351b454e6f968a324fcc77da30cf979eec57c8675de3bb92f6c21730607066226780a8d4539fcf67f9f5589d150a6c7867140b5a63de2971dc209f480c270882194f288167ed910b64cf627ea6392456fa1b648afd0b239b59652baedc595d4f87634cf7ec4262f8c9581d7f56dc6f836cfe696518ce434ef4616431d4d1b361c')

ciphertext_flag = bytes.fromhex('4b6f25623a2d3b3833a8405557e7e83257d360a054c2ea')

# Based on https://www.highgo.ca/2019/08/08/the-difference-in-five-modes-in-the-aes-encryption-algorithm/ when a key is reused the XOR component will be the same for all ciphertext
xor_component = byte_xor(test_message[0:len(ciphertext_flag)], ciphertext_test[0:len(ciphertext_flag)])

# boom
plaintext = byte_xor(ciphertext_flag, xor_component)
print(plaintext)
