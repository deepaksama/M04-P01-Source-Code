import hashlib
from inspect import signature
import json
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#import binascii

class Account:
    # Default balance is 100 if not sent during account creation
    # nonce is incremented once every transaction to ensure tx can't be replayed and can be ordered (similar to Ethereum)
    # private and public pem strings should be set inside __generate_key_pair
    def __init__(self, sender_id, balance=100):
        self._id = sender_id
        self._initial_balance = balance
        self._balance = balance
        self._nonce = 0
        self._private_pem = None
        self._public_pem = None
        self.__generate_key_pair()

    @property
    def id(self):
        return self._id

    @property
    def public_key(self):
        return self._public_pem

    @property
    def balance(self):
        return self._balance

    @property
    def initial_balance(self):
        return self._initial_balance

    def increase_balance(self, value):
        self._balance += value

    def decrease_balance(self, value):
        self._balance -= value

    def __generate_key_pair(self):
        # Generating the private/public key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Assigning the public key from the pair
        public_key = private_key.public_key()

        # Serializing the private key data to show what the file pem data looks like
        self._private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serializing the public key data to show what the file pem data looks like
        self._public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # Creates pre-hashed mesage
    def __get_hash(self, message):
        # Serialize transaction data with keys ordered, and then convert to bytes format
        hash_string = json.dumps(message, sort_keys=True)
        encoded_hash_string = hash_string.encode('utf-8')

        # Take sha256 hash of the serialized message, and then convert to bytes format
        message_hash = hashlib.sha256(encoded_hash_string).hexdigest()
        encoded_message_hash = message_hash.encode('utf-8')

        return encoded_message_hash

    def create_transaction(self, receiver_id, value, tx_metadata=''):
        nonce = self._nonce + 1
        transaction_message = {'sender': self._id, 'receiver': receiver_id,
                               'value': value, 'tx_metadata': tx_metadata, 'nonce': nonce}

        # Create private key object from private key pem
        private_key = serialization.load_pem_private_key(
            self._private_pem,
            password=None, backend=None
        )

        # Creates pre-hashed mesage
        encoded_message_hash = self.__get_hash(transaction_message)

        # Sign the encoded hash message using private key
        unformatted_signature = private_key.sign(encoded_message_hash, padding.PSS(mgf=padding.MGF1(
            hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

        # Signature - Base64 Encode and then decode to bytes to get the signature
        signature = base64.b64encode(unformatted_signature).decode('utf-8')

        self._nonce = nonce

        return {'message': transaction_message, 'signature': signature}
