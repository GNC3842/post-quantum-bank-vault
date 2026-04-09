"""Sommaire: Gère le chiffrement symétrique des données réelles :

derive_key(shared_secret) → transforme le secret KEM en clé AES-256 via HKDF

encrypt(key, plaintext) → chiffre un message avec AES-256-GCM

decrypt(key, nonce, ciphertext) → déchiffre


 """