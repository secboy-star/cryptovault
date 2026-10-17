def caesar_encrypt(plaintext, shift):
    result = []
    for char in plaintext: 
        if char.isalpha():
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

if __name__ == "__main__":
    message = "Hellow Wörld! 2026"
    encrypted = caesar_encrypt(message, 13)
    print (f"Original: {message}")
    print (f"Chiffre: {encrypted}")
    print (f"Dechiffre: {caesar_decrypt(encrypted, 13)}")
    
