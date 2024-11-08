# COCO's Collection of Circuits

**COCO** stands for *Collaborative Oblivious Computation for Orthogonal Authentication*. This collection of circuits is named in dedication to **Divya Jyoti Das** (alias: *Coco*), whose unwavering support and encouragement made this work possible.

## Dependency Folders

- **aes**: Contains the `aes128_full.txt` circuit, required for generating AES in Galois/Counter Mode (GCM) circuits.
- **sha**: Contains the `sha-256-multiblock-aligned.txt` circuit, required for generating TLS Handshake and Application-related circuits.

## Major Folders

- **aes-gcm**: This folder contains the circuit for AES-128 in GCM mode.
- **tlsv13**: This folder contains the circuits required for conducting a TLS v1.3 session.

## License Information

This repository is dual-licensed due to its foundation on previous work found at [n-for-1-auth/circuits](https://github.com/n-for-1-auth/circuits.git), licensed under the Apache License 2.0. The current repository is licensed under GPLv3, incorporating both licenses.

---

## Dedication

This work is lovingly dedicated to **Divya Jyoti Das** (*alias: Coco*), *Forensic Scientist*, whose constant support and encouragement were instrumental in its creation. The name **COCO** not only represents *Collaborative Oblivious Computation for Orthogonal Authentication* but also serves as a heartfelt tribute to her. This collection of circuits is part of an ongoing authentication library named **COCO**, a personal and professional dedication.
