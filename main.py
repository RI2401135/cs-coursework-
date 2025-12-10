import key_gen
import encryption
import decryption

def get_block_input(prompt, required_length_hex=16):
    """
    Acquires a 64-bit block (16 hexadecimal characters) from the user.
    Applies zero padding (0s) if the input is shorter.
    """
    while True:
        user_input = input(prompt).strip()
        
        #  Ensure input contains only valid hex characters.
        if not all(c in '0123456789abcdefABCDEF' for c in user_input.lower()):
            print("ERROR: Input must consist only of hexadecimal characters (0-9, A-F). Please retry.")
            continue
            
        # Ensure input does not exceed the 64-bit limit.
        if len(user_input) > required_length_hex:
            print(f"ERROR: Input exceeds the required {required_length_hex} hex characters (64 bits).")
            continue
            
        #  (Simple Zero Padding): Pad with leading zeros if necessary.
        if len(user_input) < required_length_hex:
            padding_needed = required_length_hex - len(user_input)
            padded_input = user_input.zfill(required_length_hex)
            
            print(f"NOTE: Input padded with {padding_needed} leading zeros (0s) to meet the 64-bit block size.")
            return padded_input.lower()
        
        #  Return the 16-character hex string.
        return user_input.lower()

def main():
    """
    The main execution function that guides the user through the DES algorithm cycle.
    """
    print("=" * 60)
    print("           Data Encryption Standard (DES) Implementation          ")
    print("=" * 60)
 
    
    # Get key and convert it to binary for processing
    key_prompt = "Enter the 64-bit Master Key (16 hex chars): "
    key_hex = get_block_input(key_prompt, 16)
    key_bin = key_gen.hex_to_bin(key_hex, 64)
    
    print("\n[INFO] Starting Key Schedule generation...")
    # Calls the generate_keys function from key_gen.py
    subkeys = key_gen.generate_keys(key_bin)
    print("[INFO] 16 round subkeys (K1 through K16) successfully generated.")

    
    
    while True:
        print("\n" + "-"*60)
        
        # Plaintext Input 
        plaintext_hex = get_block_input("Enter the Plaintext message block (16 hex chars): ", 16)
        plaintext_bin = key_gen.hex_to_bin(plaintext_hex, 64)


        # Calls the encryption function from encryption.py
        ciphertext_bin = encryption.encrypt_block(plaintext_bin, subkeys)
        ciphertext_hex = key_gen.bin_to_hex(ciphertext_bin)

        print(f"Padded Plaintext (Hex):  {plaintext_hex}")
        print(f"Ciphertext (Hex Output): {ciphertext_hex}")
        
        # Decryption Prompt
        decrypt_choice = input("\nDo you wish to DECRYPT the ciphertext back to plaintext? (y/n): ").strip().lower()
        
        if decrypt_choice.startswith('y'):
            # Decryption
            print("\n--- DECRYPTION PROCESS ---")
            # Calls the decryption function from decryption.py
            decrypted_bin = decryption.decrypt_block(ciphertext_bin, subkeys)
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
            print("\n" + "="*60)
            print("DES program terminated.")
            print("="*60)
            break

if __name__ == "__main__":
    main()


