
import key_gen
import encryption
import decryption
import re
import random 

def set_des_odd_parity(key_bytes: bytes) -> bytes:
    adjusted = bytearray()
    for b in key_bytes:
        ones = ((b >> 1) & 0x7F).bit_count()
        lsb = 1 if (ones % 2 == 0) else 0     
        adjusted.append((b & 0xFE) | lsb)     
    return bytes(adjusted)

def generate_random_des_key_hex_with_parity() -> str:
    
    raw = bytearray()
    for _ in range(8):
        b = random.getrandbits(8) & 0xFE
        
        raw.append(b)
    key_with_parity = set_des_odd_parity(bytes(raw))
    return key_with_parity.hex()


def get_block_input(prompt: str, required_length_hex: int = 16) -> str:
   
    hex_re = re.compile(r'^[0-9a-fA-F]+$')

    while True:
        user_input = input(prompt).strip()
        if user_input != "" and not hex_re.match(user_input):
            print("ERROR: Input must consist only of hexadecimal characters (0-9, A-F). Please retry.")
            continue

        if len(user_input) > required_length_hex:
            print(f"ERROR: Input exceeds the required {required_length_hex} hex characters (64 bits).")
            continue

        # Pad with zeros to the required length
        if len(user_input) < required_length_hex:
            padding_needed = required_length_hex - len(user_input)
            padded_input = user_input.zfill(required_length_hex)
            print(f"NOTE: Input padded with {padding_needed} zeros (0s) to meet the 64-bit block size.")
            return padded_input.lower()

        # Exactly required length
        return user_input.lower()


def main():


    key_hex = generate_random_des_key_hex_with_parity()
    print(f"[INFO] Random DES key (hex, odd parity): {key_hex}")
    key_bin = key_gen.hex_to_bin(key_hex, 64)
    print("\n[INFO] Starting Key Schedule generation...")
    subkeys = key_gen.generate_keys(key_bin)
    print("[INFO] 16 round subkeys (K1 through K16) successfully generated.")
    
    while True:

        # Plaintext Input
        plaintext_hex = get_block_input("Enter the Plaintext message block (16 hex chars): ", 16)
        plaintext_bin = key_gen.hex_to_bin(plaintext_hex, 64)

        # Encrypt
        try:
            ciphertext_bin = encryption.encrypt_block(plaintext_bin, subkeys)
        except Exception as e:
            print(f"❌ ERROR during encryption: {e}")
            continue

        ciphertext_hex = key_gen.bin_to_hex(ciphertext_bin)

        print(f"Padded Plaintext (Hex):  {plaintext_hex}")
        print(f"Ciphertext (Hex Output): {ciphertext_hex}")

        # Decryption Prompt
        decrypt_choice = input("\nDo you wish to DECRYPT the ciphertext back to plaintext? (y/n): ").strip().lower()

        if decrypt_choice.startswith('y'):
            print("\n--- DECRYPTION PROCESS ---")
            try:
                decrypted_bin = decryption.decrypt_block(ciphertext_bin, subkeys)
            except Exception as e:
                print(f"❌ ERROR during decryption: {e}")
                continue

            decrypted_hex = key_gen.bin_to_hex(decrypted_bin)
            print(f"Decrypted Plaintext (Hex): {decrypted_hex}")

            if decrypted_hex == plaintext_hex:
                print("✅ Decryption successful. Output matches original padded plaintext.")
            else:
                print("❌ ERROR: Decrypted text does not match the original plaintext.")
        else:
            print("Decryption phase skipped. End.")

        continue_choice = input("\nDo you want to process a new message block? (y/n): ").strip().lower()
        if not continue_choice.startswith('y'):
            print("Exiting program")
            break


if __name__ == "__main__":
    main()