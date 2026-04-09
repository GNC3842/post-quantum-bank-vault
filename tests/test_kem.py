# tests/test_kem.py
import pytest
from core.kem import generate_keypair, encapsulate, decapsulate


def test_keypair_generation():
    """Les clés générées doivent être des bytes non vides."""
    pk, sk = generate_keypair()

    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) > 0
    assert len(sk) > 0


def test_keypair_sizes():
    """ML-KEM-768 a des tailles de clés fixes et connues."""
    pk, sk = generate_keypair()

    # Tailles standard ML-KEM-768 (NIST FIPS 203)
    assert len(pk) == 1184, f"Taille pk inattendue : {len(pk)}"
    assert len(sk) == 2400, f"Taille sk inattendue : {len(sk)}"


def test_shared_secret_identique():
    """
    Scénario complet :
    - Serveur génère ses clés
    - Client encapsule avec la clé publique du serveur
    - Serveur décapsule avec sa clé secrète
    - Les deux shared_secrets doivent être identiques
    """
    # Serveur (banque)
    pk_server, sk_server = generate_keypair()

    # Client (Alice)
    ciphertext, shared_secret_client = encapsulate(pk_server)

    # Serveur décapsule
    shared_secret_server = decapsulate(sk_server, ciphertext)

    assert shared_secret_client == shared_secret_server


def test_shared_secret_taille():
    """Le shared_secret ML-KEM-768 fait 32 bytes (256 bits)."""
    pk, sk = generate_keypair()
    _, shared_secret = encapsulate(pk)

    assert len(shared_secret) == 32, f"Taille inattendue : {len(shared_secret)}"


def test_ciphertext_taille():
    """Le ciphertext ML-KEM-768 fait 1088 bytes."""
    pk, _ = generate_keypair()
    ciphertext, _ = encapsulate(pk)

    assert len(ciphertext) == 1088, f"Taille inattendue : {len(ciphertext)}"


def test_shared_secrets_differents_entre_sessions():
    """
    Deux sessions indépendantes doivent produire des shared_secrets différents.
    Propriété fondamentale : pas de réutilisation de secret.
    """
    pk, sk = generate_keypair()

    _, secret_1 = encapsulate(pk)
    _, secret_2 = encapsulate(pk)

    assert secret_1 != secret_2


def test_mauvaise_cle_secrete():
    """
    Décapsuler avec une mauvaise clé secrète doit produire
    un shared_secret différent — jamais une exception révélatrice.
    Propriété de sécurité : échec silencieux (IND-CCA2).
    """
    pk_legitime, _  = generate_keypair()
    _, sk_attaquant = generate_keypair()  # mauvaise clé

    ciphertext, shared_secret_client = encapsulate(pk_legitime)
    shared_secret_faux = decapsulate(sk_attaquant, ciphertext)

    # Le secret obtenu avec la mauvaise clé doit être différent
    assert shared_secret_client != shared_secret_faux