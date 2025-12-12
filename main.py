
from encryption import encrypt_block
from decryption import decrypt_block
from key_gen import generate_keys

# --- Padding & Helper Functions ---

def pad_zero(data):
    """Adds null bytes (b'\x00') to fill the last block (8-byte block size)."""
    block_size = 8
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 8 and len(data) > 0: 
        padding_len = 0
    return data + b'\x00' * padding_len

def unpad_zero(data):
    """Removes trailing null bytes (b'\x00')."""
    return data.rstrip(b'\x00')

def bytes_to_bitstring(data):
    """Convert bytes to a bitstring."""
    return ''.join(f'{b:08b}' for b in data)

def bitstring_to_bytes(bitstring):
    """Convert a bitstring to bytes."""
    # Ensure it's a multiple of 8 bits
    if len(bitstring) % 8 != 0:
        bitstring = bitstring.ljust((len(bitstring) + 7) // 8 * 8, '0')
    return bytes(int(bitstring[i:i+8], 2) for i in range(0, len(bitstring), 8))

def bytes_to_64bit_key(key):
    """Convert key bytes to a 64-bit bitstring, padding or truncating as needed."""
    # DES requires exactly 64 bits (8 bytes)
    if len(key) < 8:
        # Pad with zeros
        key = key + b'\x00' * (8 - len(key))
    elif len(key) > 8:
        # Truncate to 8 bytes
        key = key[:8]
    return bytes_to_bitstring(key)

# --- Core Functions ---

def encrypt_bytes(data, key):
    """Encrypts data in ECB mode with Zero Padding using DES."""
    # Generate round keys from the key
    key64 = bytes_to_64bit_key(key)
    round_keys = generate_keys(key64)
    
    # Pad the data
    padded_data = pad_zero(data)
    
    # Convert to bitstrings and encrypt block by block
    out = bytearray()
    for i in range(0, len(padded_data), 8):
        block_bytes = padded_data[i:i+8]
        # Ensure exactly 8 bytes (pad with zeros if needed)
        if len(block_bytes) < 8:
            block_bytes = block_bytes + b'\x00' * (8 - len(block_bytes))
        block64 = bytes_to_bitstring(block_bytes)
        # Should be exactly 64 bits now
        
        encrypted_block = encrypt_block(block64, round_keys)
        # Encrypted block is exactly 64 bits, convert to 8 bytes
        out.extend(bitstring_to_bytes(encrypted_block)[:8])
    
    return bytes(out)

def decrypt_bytes(data, key):
    """Decrypts data in ECB mode and removes Zero Padding using DES."""
    # Generate round keys from the key
    key64 = bytes_to_64bit_key(key)
    round_keys = generate_keys(key64)
    
    # Decrypt block by block
    out = bytearray()
    for i in range(0, len(data), 8):
        block_bytes = data[i:i+8]
        # Ensure exactly 8 bytes (pad with zeros if needed)
        if len(block_bytes) < 8:
            block_bytes = block_bytes + b'\x00' * (8 - len(block_bytes))
        block64 = bytes_to_bitstring(block_bytes)
        # Should be exactly 64 bits now
        
        decrypted_block = decrypt_block(block64, round_keys)
        # Decrypted block is exactly 64 bits, convert to 8 bytes
        out.extend(bitstring_to_bytes(decrypted_block)[:8])
    
    # Remove padding
    return unpad_zero(bytes(out))


# --- Main Execution ---

if __name__ == "__main__":
    
    key = b'SECRETKEY'
    
    # Get plaintext from user
    user_input = input("Enter plaintext to encrypt: ")
    plaintext = user_input.encode('utf-8')
    
    # 1. Encryption
    ciphertext = encrypt_bytes(plaintext, key)
    
    # 2. Decryption
    decrypted_data = decrypt_bytes(ciphertext, key)
    
    # 3. Output
    print(f"Original: {user_input}")
    print(f"Ciphertext (Hex): {ciphertext.hex()}")
    decrypted_text = decrypted_data.decode('utf-8')
    print(f"Decrypted: {decrypted_text}")
    
    if decrypted_data == plaintext:
        print("Verification: SUCCESS")
    else:
        print("Verification: FAILURE")
