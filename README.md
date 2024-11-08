# COCO's Collection of Circuits

**COCO** stands for *Collaborative Oblivious Computation for Orthogonal Authentication*. This collection of circuits is named in dedication to **Divya Jyoti Das** (alias: *Coco*), whose unwavering support and encouragement made this work possible.

## Dependency Folders

- **aes**: Contains the `aes128_full.txt` circuit, required for generating AES in Galois/Counter Mode (GCM) circuits.
- **sha**: Contains the `sha-256-multiblock-aligned.txt` circuit, required for generating TLS Handshake and Application-related circuits.

## Major Folders

- **aes-gcm**: This folder contains the circuit for AES-128 in GCM mode.
- **tlsv13**: This folder contains the circuits required for conducting a TLS v1.3 session.

## Important Notes

### Optimization and Industry Readiness

This work is not industry-ready and can be further optimized as required. The circuits provided here can benefit from more efficient implementations of certain cryptographic operations using the EMP-toolkit. For example:
- **AES-128 in GCM**: Could utilize a more optimized implementation of Galois Field multiplication.
- **TLS v1.3 circuits**: Can take advantage of EMP-tool's Pseudo-Random Generator (PRG) to enhance efficiency and reduce redundancy.

### Memory Leak Consideration

The memory leak issue in the [n-for-1-auth/circuits](https://github.com/n-for-1-auth/circuits) repository, fixed in commit `35135df7b05ad2c0cba3e0bfffea8641d6629a9e`, has been taken into account in this repository. The TLS cryptographic preliminary generation circuits are based on the version of that repository after this fix, ensuring improved memory management.

## License

This repository is dual-licensed:

- **GPLv3**: This work, including any modifications, is licensed under the [GNU General Public License, Version 3 (GPLv3)](LICENSE).
- **Apache 2.0**: Some portions of this repository are based on works licensed under the [Apache License, Version 2.0](LICENSE-APACHE) from [n-for-1-auth/circuits](https://github.com/n-for-1-auth/circuits).

You may choose to use this work under either license, but any modifications to the Apache-licensed portions are licensed under GPLv3.

---

## Dedication

This work is lovingly dedicated to **Divya Jyoti Das** (*alias: Coco*), *Forensic Scientist*, whose constant support and encouragement were instrumental in its creation. The name **COCO** not only represents *Collaborative Oblivious Computation for Orthogonal Authentication* but also serves as a heartfelt tribute to her. This collection of circuits is part of an ongoing authentication library named **COCO**, a personal and professional dedication.
