from key_gen import permute 
# Assumes feistel, xor_bits, IP, and FP are in encryption
from encryption import feistel, xor_bits, IP, FP 

def decrypt_block(block64, round_keys):
    """
    Performs the 16-round DES decryption.
    The subkeys are applied in the reverse order (K16, K15, ..., K1).
    """
    # IP on the ciphertext block
    ip = permute(block64, IP)
    # Split the block
    L, R = ip[:32], ip[32:] 

    # Decryption requires the subkeys in REVERSE ORDER
    reversed_keys = round_keys[::-1]

    #  16 Rounds  
    for i in range(16):
        K_i = reversed_keys[i] # Current decryption round key

        L_prev = L 
        new_L = R
        f_output = feistel(R, K_i)
        new_R = xor_bits(L_prev, f_output)

        L, R = new_L, new_R # Updating the halves

    # Final Permutation
    pre_fp_block = L + R

    # Final Permutation 
    plaintext = permute(pre_fp_block, FP)
    return plaintext