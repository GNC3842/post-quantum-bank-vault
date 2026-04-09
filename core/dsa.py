"""Sommaire: Encapsule toute la logique ML-DSA-65 (signature numérique post-quantique) 
Ce fichier gère l'authentification post-quantique avec ML-DSA-65

generate_keypair() → le client génère ses clés de signature

sign(sk, message) → le client signe sa demande

verify(pk, message, signature) → la banque vérifie l'identité du client

"""

#Fonctionnement
# 1.Le client génère une clef secrete + publique
# 2.Le client signe sa demande avec sa clef secrete => siganture unique (basé sur la clef + message)
# 3.Le serveru vérifie la signature avec la clef publique

import warnings
import oqs
 
warnings.filterwarnings("ignore", category=UserWarning, module="oqs")

DSA_ALGORITHM = "ML-DSA-65"

def generate_keypair():
  """
  Génère une paire de clefs ML-DSA pour le client

  Return:
      pk  -clef publique à transmettre au serveur
      sk  -clef privée à garder localement
  """
  with oqs.Signature(DSA_ALGORITHM) as dsa:
    pk = dsa.generate_keypair()
    sk = dsa.export_secret_key()
  return pk,sk


def signer(sk,message):
  """
  Genre la signature unique associé à ce message + celf secrete
  Args:
      sk:clef secrete du client
      message:le message du client
  Return:
      siganture -la signature unique
  """
  #on travaille que sur des bytes
  if type(message) == str:
    message = message.encode('UTF-8') 

  with oqs.Signature(DSA_ALGORITHM,secret_key=sk) as dsa:
    signature = dsa.sign(message=message)
  return signature


def verify(pk,message,signature):
  """_summary_

  Args:
      pk: clef publique du client
      message: message reçu
      signature: signature recu avec le message
  Return:
      True  - si la signature est valide
      False -sinon
  """
  #on ne travaille que sur des butes
  if type(message) == str:
    message = message.encode("utf-8")
  
  with oqs.Signature(DSA_ALGORITHM) as verificateur:
    result = verificateur.verify(message=message,signature=signature,public_key=pk)
  return result
  
