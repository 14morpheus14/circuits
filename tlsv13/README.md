# TLS v1.3 Bristol Circuits

This folder contains the circuits required for conducting a TLS v1.3 session. These circuits are specifically designed for TLS v1.3 and have been assembled using multithreading enabled in the EMP-Toolkit. Below is a description of each circuit and its input/output sequence.

## Circuits

### 1. DeriveHandshakeSecret_PreMasterSecret.txt
- **Alice Input Sequence**: Shared Secret of Alice (256 bits), Output Mask of Alice (256 bits)
- **Bob Input Sequence**: Shared Secret of Bob (256 bits), Output Mask of Bob (256 bits)
- **Output Sequence**: Handshake Secret share of Alice XOR masked with Output Mask of Alice (256 bits), Handshake Secret share of Bob XOR masked with Output Mask of Bob (256 bits)

### 2. DeriveHandshakeCryptographicPrelims.txt
- **Alice Input Sequence**: Handshake Secret share of Alice (256 bits), Handshake Hash/Hello Hash (256 bits)
- **Bob Input Sequence**: Handshake Secret share of Bob (256 bits)
- **Output Sequence**: Client Handshake Secret (256 bits), Server Handshake Secret (256 bits)

### 3. DeriveApplicationCryptographicPrelims.txt
- **Alice Input Sequence**: Handshake Secret Share of Alice (256 bits), Handshake Hash (256 bits), Output Mask of Alice (128 bits)
- **Bob Input Sequence**: Handshake Secret Share of Bob (256 bits), Output Mask of Bob (128 bits)
- **Output Sequence**: Client Application Key Share of Alice XOR masked Output Mask of Alice (128 bits), Client Application Key Share of Bob XOR masked Output Mask of Bob (128 bits), Client Application IV (96 bits), Server Application Traffic Secret (256 bits)

### 4. DeriveSMTPRCPTTOCommandCiphertext.txt
- **Alice Input Sequence**: TLS v1.3 AAD (40 bits), TLS v1.3 IV (96 bits), Client Application Key Share of Alice (128 bits), Email ID share of Alice (432 bits - should be whitespace padded if email ID length < 432 bits)
- **Bob Input Sequence**: Client Application Key Share of Bob (128 bits), Email ID share of Bob (432 bits - should be whitespace padded if email ID length < 432 bits)
- **Output Sequence**: RCPT TO Command Ciphertext (512 bits), Tag (128 bits)

### 5. DeriveSMTPTOCommandCiphertext.txt
- **Alice Input Sequence**: TLS v1.3 AAD (40 bits), TLS v1.3 IV (96 bits), Client Application Key Share of Alice (128 bits), Email ID share of Alice (432 bits - should be whitespace padded if email ID length < 432 bits)
- **Bob Input Sequence**: Client Application Key Share of Bob (128 bits), Email ID share of Bob (432 bits - should be whitespace padded if email ID length < 432 bits)
- **Output Sequence**: TO Command Ciphertext (512 bits), Tag (128 bits)

### 6. DeriveTLSCiphertext.txt
- **Alice Input Sequence**: TLS v1.3 AAD (40 bits), TLS v1.3 IV (96 bits), Client Application Key Share of Alice (128 bits), Plaintext (512 bits)
- **Bob Input Sequence**: Client Application Key Share of Bob (128 bits)
- **Output Sequence**: Ciphertext (512 bits), Tag (128 bits)

### 7. DeriveTLSSharedPlaintextCiphertext.txt
- **Alice Input Sequence**: TLS v1.3 AAD (40 bits), TLS v1.3 IV (96 bits), Client Application Key Share of Alice (128 bits), Plaintext share of Alice (512 bits)
- **Bob Input Sequence**: Client Application Key Share of Bob (128 bits), Plaintext share of Bob (512 bits)
- **Output Sequence**: Ciphertext (512 bits), Tag (128 bits)

---

## License Information

These circuits are based on previous works and circuits that were licensed under the Apache License 2.0. As a result of modifications and further development, this work is now licensed under the GNU General Public License, Version 3 (GPLv3). The original Apache 2.0 license is acknowledged, and the resulting derived work is redistributed here under GPLv3.
