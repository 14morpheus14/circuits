# AES-128 GCM Circuit

This circuit is licensed under the GNU General Public License, Version 3 (GPLv3).

### Based on:
- **NIST Special Publication 800-38D**: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC, by Morris Dworkin.
- **The Galois/Counter Mode of Operation (GCM)**: by David A. McGrew, Cisco Systems, Inc., and John Viega, Secure Software.

### Source and License Information
This file is based on the `aes-128-full.txt` circuit, which was taken from the following repository:
- https://github.com/n-for-1-auth/circuits/blob/main/aes/aes128_full.txt

The original `aes-128-full.txt` circuit is licensed under the Apache License, Version 2.0.

This derived work retains the original notice and has been modified and redistributed here under GPLv3.

### Description
This circuit computes AES-128 in Galois Counter Mode (GCM) given a 512-bit plaintext and a 40-bit Additional Authentication Data (AAD) input. It is specifically designed for use in TLS 1.3, providing encryption and authentication in a single operation.

### Usage
The circuit expects input in the following sequence:
- **AAD**: 40 bits
- **IV**: 96 bits
- **Key**: 128 bits
- **Plaintext**: 512 bits

The output is provided in the following sequence:
- **Ciphertext**: 512 bits
- **Tag**: 128 bits
