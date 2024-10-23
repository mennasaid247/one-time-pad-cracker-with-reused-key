#description of my approach
#first i convert the hexadecimal ciphertexts to byte string  and call this function (decrypt_key_from_spaces)
#this function is responsible for find parts of the key and to find spaces and some letters of decrypted ciphers
#by identifying spaces in the ciphertexts then loop on each ciphertext and xor the current byte(encrypted space)
# with the same position of another ciphertexts to identify spaces(when result of xor is zero)/letters(when result of xor is alphabetic)
#as when space is xored with letter it gives the same letter but with flipped case
#then parts of key is derived and partial decrypted ciphers are derived
# so the output i managed to reach automatically before making any guesse is the following:
#Output before guesses:
# Sentence 1: -od-rn cryptogra--- -equ--es c---ful a-- -ig-r-u- a-a-----
# Sentence 2: -dd-ess randomiz---o- co--d pr---nt ma--c-ou- -a-l -t-----
# Sentence 3: -t -s not practi--- -o r--y so---y on --m-et-i- -nc-y-----
# Sentence 4: - s-all never re--- -he --me p---word -- -ul-i-l- a-c-----
# Sentence 5: -ee- review of s---r-ty --chan---s red--e- v-l-e-ab-l-----
# Sentence 6: -ea-ning how to ---t- se--re s---ware -- - n-c-s-ar- -----
# Sentence 7: -ec-re key excha--- -s n--ded --- symm--r-c -e- -nc-y-----
# Sentence 8: -ec-rity at the ---e-se -- usa---ity c--l- d-m-g- s-c-----
#then i make guess for sentence 7 to be likely "secure key exchange is needed for symmetric key encryption"
#then i use the function recover_key to recover the complete key from the plaintext i have guessed and its ciphertext
#then i use the key to decrypt the rest of ciphers as the same key is used across all messages(to verify my guesses)
#Output after decryption:
# Sentence 1 : modern cryptography requires careful and rigorous analysis
# Sentence 2 : address randomization could prevent malicious call attacks
# Sentence 3 : it is not practical to rely solely on symmetric encryption
# Sentence 4 : i shall never reuse the same password on multiple accounts
# Sentence 5 : peer review of security mechanisms reduces vulnerabilities
# Sentence 6 : learning how to write secure software is a necessary skill
# Sentence 7 : secure key exchange is needed for symmetric key encryption
# Sentence 8 : security at the expense of usability could damage security

from typing import List
import binascii

CIPHERTEXTS = [
    "F9B4228898864FCB32D83F3DFD7589F109E33988FA8C7A9E9170FB923065F52DD648AA2B8359E1D122122738A8B9998BE278B2BD7CF3313C7609",
    "F5BF229F8F9B1C8832C0212DFD7F92EA18FF29C7E6C968848D6EFAC16074F129D640AB67CE59E3DC6109212AB4EB959FFD34F3B269EB292C7409",
    "FDAF668499C801C734813F3BF3718FF91AEA2C88FC862B999D6EE7C16369F83ADF57FF28CD18FCCC6F0D2B2BB5A295DEF436B0A164EF3C267014",
    "FDFB35858B8403882EC4392CE03289F50CF82588FC816ECB8B63F3843076F52CC059B035C718E0DB220D3B33B3A28692F478B2B07EF03D216B09",
    "E4BE239FCA9A0ADE29C43869FD74DBE31CE835DAE19D72CB9567FD897168FD2CDE5DFF35C65CFAD667136E29B2A7989BE339B1BA71F63C267A09",
    "F8BE279F848101CF60C9203EB26694B00EF929DCEDC9788E9B77EC843075FB39C759BE35C618E6C622016E31A2A8938DE239A1AA3DEC23267316",
    "E7BE2598988D4FC325D86F2CEA7193F117EC2588E19A2B859D67FA847426F230C10EAC3ECE55EAC170092D7FACAE8FDEF436B0A164EF3C267014",
    "E7BE259898811BD160C03B69E67A9EB01CF330CDE69A6ECB9764BE946367F636DF47AB3E835BE0C06E046E3BA6A69799F478A0B67EEA3A266B03"
]
space = ord(' ')

#check if the current byte is encrypted space
def check_is_space(ciphertexts, current, col) :
    for cipher in ciphertexts:
        xor_result = cipher[col] ^ current # xor the current byte with bytes from other ciphers
        # Check if the XOR result is alphabetic or zero (indicating a space)
        if xor_result != 0 and not chr(xor_result).isalpha(): 
            return False  #not valid so not space
    return True


def decrypt_from_spaces(ciphertexts, partial_dec_text) :
    key_length = len(ciphertexts[0]) #set size of key by length of ciphertext as all of same length
    key = bytearray(key_length) #hold the partial derived  key
    key_pos = []
    for _ in range(key_length):     #boolean to see which pos in key is known at first all false
            key_pos.append(False)
    for col in range(key_length): # loop on each character  in the ciphertexts
        for cipher in ciphertexts:
            # check if current char is  encrypted space then xor it with space to derive part of key byte and mark position as known.
            if check_is_space(ciphertexts, cipher[col], col): 
                key[col] = cipher[col] ^ space
                key_pos[col] = True
                row = 0
                #loop on each ciphertext and xor the current byte with the same position of another ciphertexts
                #to identify spaces/letters
                for clear_row in range(len(partial_dec_text)):
                    if len(partial_dec_text[clear_row]) != 0 and col < len(partial_dec_text[clear_row]):
                        #  xor the current byte with the same position(col) of another ciphertexts
                        result = cipher[col] ^ ciphertexts[row][col]
                        if result == 0: #xor space with space is 0
                            partial_dec_text[clear_row][col] = space
                            # xor with space flips letter case
                        elif chr(result).isupper():  
                            partial_dec_text[clear_row][col] = ord(chr(result).lower())
                        elif chr(result).islower():  
                            partial_dec_text[clear_row][col] = ord(chr(result).upper())
                        row =row+ 1
    # to show known key parts as hex and unknown parts as '__'               
    partial_decr_key_value = ''.join('{0:02x}'.format(key[pos]) if key_pos[pos] else '__' for pos in range(key_length))
    # print("Partial decrypted Key:", partial_decr_key_value)
    for x, msg in enumerate(partial_dec_text): # print partial decrypted ciphers
        print(f"Sentence {x + 1}: {msg.decode('ascii')}")


#to derive the full key from the plaintext and ciphertext
def derive_key(plaintext, ciphertext):
    key = bytearray(len(plaintext))
    for i in range(len(plaintext)):
        key[i] = plaintext[i] ^ ciphertext[i]
    return binascii.hexlify(key).decode('ascii')        
    

#decrypts each ciphertext using the derived key (to verid=fy gusseing)
# and stores the results in cleartexts, printing the decrypted sentences
def decrypt(ciphertexts, plaintexts, key):
    key_bytes = binascii.unhexlify(key.strip())  # Convert the input key from hex to bytes
    key_length = len(key_bytes)
    print("Sentences after decryption using key")
    for i, ciphertext in enumerate(ciphertexts):
        for j, byte in enumerate(ciphertext):
            plaintexts[i][j] = byte ^ key_bytes[j % key_length]  #xor each byte of ciphertext with key
        print(f"Sentence {i + 1}: {plaintexts[i].decode('ascii')}")  # print the decrypted sentence        


def main():
    ciphertext_7 = binascii.unhexlify(CIPHERTEXTS[6]) # convert the 7th ciphertext from hex to bytes
    message = "secure key exchange is needed for symmetric key encryption".encode('ascii') #the guessed 7th plaintext
    ciphertexts = [binascii.unhexlify(ct) for ct in CIPHERTEXTS] # convert all ciphertexts from hex to bytes
    #make partial decrypted texts 
    partial_dec_text = [bytearray(b'-' * len(line)) for line in ciphertexts] 
    decrypt_from_spaces(ciphertexts, partial_dec_text)
    # derive the full key using the guesses plaintext and its corresponding ciphertext
    recovered_key = derive_key(message, ciphertext_7)
    # to print the total key
    # print("full derived Key:",recovered_key)
    # decrypt all ciphertexts using the derived key and print the complete decrypted sentences
    decrypt(ciphertexts, partial_dec_text, recovered_key)
    


if __name__ == '__main__':
    main() # type: ignore