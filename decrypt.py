#!/usr/bin/env python3
import argparse
import sys
import hashlib
import base64
from Crypto.Cipher import AES

def deobfuscate_file(input_file, obfuscate_header, aes_key, output_file):
    """
    Decrypts the first 1024 bytes of 'input_file' using the 'obfuscate_header'
    and 'aes_key' derived from the original JS logic, then writes the result
    to 'output_file'.
    """
    # Parse the obfuscation header (expected format "1|BASE64COUNTER")
    parts = obfuscate_header.split('|')
    if len(parts) != 2:
        raise ValueError("Invalid X-Obfuscate header format.")
    version, counter_b64 = parts
    if version != '1':
        raise ValueError("Unsupported obfuscation version.")

    # Compute the AES key from the SHA-1 of the user-supplied aes_key
    sha1_key = hashlib.sha1(aes_key.encode('utf-8')).digest()[:16]

    # Decode the base64 counter
    counter_bytes = base64.b64decode(counter_b64)
    counter_int = int.from_bytes(counter_bytes, byteorder='big')

    # Read the file
    with open(input_file, 'rb') as f:
        data = f.read()

    # Decrypt first 1024 bytes via AES-CTR (64-bit block size)
    chunk_to_decrypt = data[:1024]
    cipher = AES.new(
        sha1_key,
        AES.MODE_CTR,
        nonce=b'',
        initial_value=counter_int,
        #segment_size=64
    )
    decrypted_chunk = cipher.decrypt(chunk_to_decrypt)

    # Combine decrypted bytes with the rest
    decrypted_data = bytearray(data)
    decrypted_data[0:1024] = decrypted_chunk

    # Write output
    with open(output_file, 'wb') as out:
        out.write(decrypted_data)

def main():
    parser = argparse.ArgumentParser(
        description="Deobfuscate the first 1024 bytes of a file using an X-Obfuscate header."
    )
    parser.add_argument("input_file", help="Path to the obfuscated binary file")
    parser.add_argument("obfuscate_header", help="X-Obfuscate header string (e.g. '1|<BASE64COUNTER>')")
    parser.add_argument("aes_key", help="String used to derive AES key via SHA-1")
    parser.add_argument("output_file", help="Where to write the deobfuscated file")

    args = parser.parse_args()

    deobfuscate_file(args.input_file, args.obfuscate_header, args.aes_key, args.output_file)

if __name__ == "__main__":
    main()