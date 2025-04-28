import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    # Extended Euclidean Algorithm
    d_old, d = 0, 1
    r_old, r = phi, e
    while r != 0:
        quotient = r_old // r
        d_old, d = d, d_old - quotient * d
        r_old, r = r, r_old - quotient * r
    if d_old < 0:
        d_old += phi
    return d_old

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    elif p == q:
        raise ValueError("p and q cannot be the same.")
    
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # Compute d, the modular inverse of e
    d = mod_inverse(e, phi)

    # Public key (e, n), Private key (d, n)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in plaintext]
    return cipher

def decrypt(private_key, ciphertext):
    d, n = private_key
    plain = [chr(pow(char, d, n)) for char in ciphertext]
    return ''.join(plain)

def main():
    print("RSA Encryption/Decryption")
    p = int(input("Enter a prime number (p): "))
    q = int(input("Enter another prime number (q): "))
    
    try:
        public, private = generate_keypair(p, q)
        print(f"Public key: {public}")
        print(f"Private key: {private}")

        message = input("Enter a message to encrypt: ")
        encrypted_msg = encrypt(public, message)
        print(f"Encrypted message: {encrypted_msg}")

        decrypted_msg = decrypt(private, encrypted_msg)
        print(f"Decrypted message: {decrypted_msg}")

    except ValueError as e:
        print(e)

if __name__ == '__main__':
    main()
