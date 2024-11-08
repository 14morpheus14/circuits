# Bristol Circuit Generators

This folder contains two Bristol circuit generators, `aes_128_gcm.cpp` and `tlsv13.cpp`, which run on the [EMP-Toolkit](https://github.com/emp-toolkit/emp-tool).

### Setup Instructions

1. **Copy Generators**: Copy `aes_128_gcm.cpp` and `tlsv13.cpp` to the `test` folder in the EMP-Toolkit.

2. **Modify CMakeLists.txt**: Update the `CMakeLists.txt` file in the `test` folder of EMP-Toolkit by adding the following lines:
   ```cmake
   add_test_case(aes_128_gcm)
   add_test_case(tls_v13)
   ```

3. **Copy Dependencies**: Place the `sha-256-multiblock-aligned.txt` and `aes128_full.txt` files into the `build` folder.

4. **Compile and Run**:
   - Compile the tests by running the build process in EMP-Toolkit.
   - Execute the tests with:
     ```bash
     bin/test_aes_128_gcm
     bin/test_tls_v13
     ```
   - The generated circuits will appear in the current directory.

### Circuit Generators

- **`aes_128_gcm.cpp`**: This file generates the Bristol circuit required for AES-128 in GCM mode. It requires the `aes128_full.txt` file, which can be found at:
  [aes128_full.txt](https://github.com/n-for-1-auth/circuits/blob/main/aes/aes128_full.txt)

- **`tlsv13.cpp`**: This file generates Bristol circuits for a 2-PC Secure Multiparty TLS v1.3 session. It requires:
  - The functions `DeriveHandshakeSecret_PreMasterSecret()`, `DeriveHandshakeCryptographicPrelims()`, and `DeriveApplicationCryptographicPrelims()` are based on [n-for-1-auth/circuits](https://github.com/n-for-1-auth/circuits.git) and require the file:
    [sha-256-multiblock-aligned.txt](https://github.com/n-for-1-auth/circuits/blob/main/sha256/sha-256-multiblock-aligned.txt)

  - Additional functions `DeriveSMTPRCPTTOCommandCiphertext()`, `DeriveSMTPTOCommandCiphertext()`, `DeriveTLSCiphertext()`, and `DeriveTLSSharedPlaintextCiphertext()` generate circuits for TLS v1.3-specific application data encryption, using the underlying circuit in `aes_128_gcm.cpp` for `aes-128-gcm-512-bit-plaintext-40-bit-aad.txt`.

---

This setup allows for the generation of Bristol circuits necessary for cryptographic operations in AES-128 GCM mode and TLS v1.3 secure sessions.
