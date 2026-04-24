import sys
from classical.substitution import (
    encrypt as sub_encrypt,
    decrypt as sub_decrypt,
    is_valid_key,
    frequency_analysis,
    get_letter_frequencies,
    substitution_attack_report,
    ranked_bruteforce_substitution
)
from classical.double_transposition import (  # Changed from transposition
    encrypt_double_transposition,
    decrypt_double_transposition,
    is_valid_permutation_key
)
def display_frequencies(text, label="Frequency Analysis"):
    freq = frequency_analysis(text)
    print(f"\n--- {label} ---")
    for k in sorted(freq):
        print(f"{k}: {freq[k]}")

def main():
    while True:
        print("\n=== CryptoLab Menu ===")
        print("1. Substitution Encrypt")
        print("2. Substitution Decrypt")
        print("3. Substitution Attack Analysis")
        print("4. Double Transposition Encrypt")
        print("5. Double Transposition Decrypt")
        print("6. RSA Generate Keys")
        print("7. RSA Encrypt")
        print("8. RSA Decrypt")
        print("9. Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            pt = input("Enter plaintext: ")
            key = input("Enter 26-letter key: ")
            if is_valid_key(key):
                ct = sub_encrypt(pt, key)
                print(f"Ciphertext: {ct}")
                display_frequencies(ct)
            else: print("Invalid Key.")

        elif choice == "2":
            ct = input("Enter ciphertext: ")
            key = input("Enter 26-letter key: ")
            if is_valid_key(key):
                pt = sub_decrypt(ct, key)
                print(f"Plaintext: {pt}")
                display_frequencies(ct, "Frequency Analysis (Ciphertext)")
            else: print("Invalid Key.")

        elif choice == "3":
            ct = input("Enter ciphertext for analysis: ")
            report = substitution_attack_report(ct)
            print(f"\n{report['complexity_message']}")
            print(f"Top Candidate: {report['best_candidate_text']}")
            if input("Run ranked attack? (y/n): ").lower() == 'y':
                res = ranked_bruteforce_substitution(ct)
                for i, (score, label, text) in enumerate(res["candidates"], 1):
                    print(f"{i}. [Score: {score}] {text}")

        elif choice == "4":
            pt = input("Enter plaintext: ")
            k1 = input("Key 1: ")
            k2 = input("Key 2: ")
            if is_valid_permutation_key(k1) and is_valid_permutation_key(k2):
                r1, final = encrypt_double_transposition(pt, k1, k2)
                print(f"After Round 1: {r1}\nFinal: {final}")
                display_frequencies(final)

        elif choice == "5":
            ct = input("Enter ciphertext: ")
            k1 = input("Key 1: ")
            k2 = input("Key 2: ")
            if is_valid_permutation_key(k1) and is_valid_permutation_key(k2):
                s1, orig = decrypt_double_transposition(ct, k1, k2)
                print(f"Reversed Round 2: {s1}\nPlaintext: {orig}")
                display_frequencies(ct, "Frequency Analysis (Ciphertext)")

        elif choice == "9":
            print("Exiting...")
            break
        
        elif choice in ["6", "7", "8"]:
            print("RSA Module Implementation Pending.")
        else: print("Invalid selection.")

if __name__ == "__main__":
    main()