import warnings
import oqs

"""Sommaire: Encapsule toute la logique ML-KEM-768 (échange clefs post-quantique)

generate_keypair() -> la banque génère ses clés

encapsulate(pk) → le client produit un secret + ciphertext

decapsulate(sk, ciphertext) → la banque retrouve le même secret

"""

# Supprime le warning de version mineur liboqs/liboqs-python
warnings.filterwarnings("ignore", category=UserWarning, module="oqs")

# Variante ML-KEM niveau sécurité 3
KEM_ALGORITHM = "ML-KEM-768"


def generate_keypair():
    """
    Génère une paire de clés ML-KEM pour le serveur (banque).

    Returns:
        pk : clé publique  — à transmettre au client
        sk : clé secrète   — ne quitte jamais le serveur
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


def encapsulate(pk):
    """
    Le client encapsule un secret en utilisant la clé publique du serveur.
    Produit un ciphertext à envoyer au serveur + un shared_secret local.

    Args:
        pk : clé publique du serveur

    Returns:
        ciphertext    — à envoyer au serveur
        shared_secret — secret connu uniquement du client (pour l'instant)
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(pk)
    return ciphertext, shared_secret


def decapsulate(sk):
    """
    Le serveur décapsule le ciphertext avec sa clé secrète.
    Retrouve exactement le même shared_secret que le client.

    Args:
        sk         : clé secrète du serveur
        ciphertext : reçu depuis le client

    Returns:
        shared_secret — identique à celui du client si tout va bien
    """
    with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key=sk) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret