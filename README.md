# encryptor

simple commandline encryption with passphrase

- Key for AES-256-GCM-SIV or XChaCha20 is derived with Argon2i, with the BLAKE3 hash of passphrase as salt.
