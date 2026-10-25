import string
def caesar_encrypt(plaintext, shift):
    result = []
    for char in plaintext: 
        if char in string.ascii_letters:
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)
    return "".join(result)

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

def caesar_brute_force(ciphertext):
    for shift in range(26):
        print(f"Shift {shift:2d}: {caesar_decrypt(ciphertext, shift)}")

def vigenere_encrypt(plaintext, key):
    result =[]
    if not key.isalpha() or not key.isascii():
        raise ValueError("La cle doit contenir uniquement des lettres A-Z")
    key = key.upper()
    key_index = 0
    for char in plaintext:
        if char in string.ascii_letters:
            shift = ord (key[key_index % len(key)]) - ord("A")
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)

def vigenere_decrypt(ciphertext, key):
    result = []
    if not key.isalpha() or not key.isascii():
        raise ValueError("La cle doit contenir uniquement des lettres A-Z")
    key = key.upper()
    key_index = 0
    for char in ciphertext:
        if char in string.ascii_letters:
            shift = ord(key[key_index % len(key)]) - ord("A")
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

xor_decrypt = xor_encrypt

if __name__ == "__main__":
    
    message = b"Donnees sensibles"
    key = b"CLE_SECRETE"
    encrypted = xor_encrypt(message, key)
    decrypted = xor_decrypt(encrypted, key)
    print(f"Chiffre: {encrypted.hex()}")
    print(f"Dechiffre: {decrypted}")
    print(xor_encrypt(encrypted, message))
    tampered = bytearray(encrypted)
    tampered[0] ^= 0x01
    print(xor_decrypt(bytes(tampered), key))
    
    """
    message = "Hellow Wörld! 2026"
    encrypted = caesar_encrypt(message, 13)
    print (f"Original: {message}")
    print (f"Chiffre: {encrypted}")
    print (f"Dechiffre: {caesar_decrypt(encrypted, 13)}")
    
    msg = "NHAR KBIR HADA ASSI SALMI"
    key = "key"
    enc = vigenere_encrypt(msg, key)
    print(f"Cle: {key} | Chiffre :{enc}")
    print(f"Dechiffre: {vigenere_decrypt(enc, key)}")
    """

