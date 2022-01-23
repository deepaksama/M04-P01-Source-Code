from email import message
import json
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from Block import Block


class Blockchain:
    # Basic blockchain init
    # Includes the chain as a list of blocks in order, pending transactions, and known accounts
    # Includes the current value of the hash target. It can be changed at any point to vary the difficulty
    # Also initiates a genesis block
    def __init__(self, hash_target):
        self._chain = []
        self._pending_transactions = []
        self._chain.append(self.__create_genesis_block())
        self._hash_target = hash_target
        self._accounts = {}

    def __str__(self):
        return f"Chain:\n{self._chain}\n\nPending Transactions: {self._pending_transactions}\n"

    @property
    def hash_target(self):
        return self._hash_target

    @hash_target.setter
    def hash_target(self, hash_target):
        self._hash_target = hash_target

    # Creating the genesis block, taking arbitrary previous block hash since there is no previous block
    # Using the famous bitcoin genesis block string here :)  
    def __create_genesis_block(self):
        genesis_block = Block(0, [], 'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks', 
            None, 'Genesis block using same string as bitcoin!')
        return genesis_block

    def __validate_transaction(self, transaction):
        # Serialize transaction data with keys ordered, and then convert to bytes format
        hash_string = json.dumps(transaction['message'], sort_keys=True)
        encoded_hash_string = hash_string.encode('utf-8')
        
        # Take sha256 hash of the serialized message, and then convert to bytes format
        message_hash = hashlib.sha256(encoded_hash_string).hexdigest()
        encoded_message_hash = message_hash.encode('utf-8')

        # Signature - Encode to bytes and then Base64 Decode to get the original signature format back 
        signature = base64.b64decode(transaction['signature'].encode('utf-8'))

        try:
            # Load the public_key object and verify the signature against the calculated hash
            sender_public_pem = self._accounts.get(transaction['message']['sender']).public_key
            sender_public_key = serialization.load_pem_public_key(sender_public_pem)
            sender_public_key.verify(
                                        signature,
                                        encoded_message_hash,
                                        padding.PSS(
                                            mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=padding.PSS.MAX_LENGTH
                                        ),
                                        hashes.SHA256()
                                    )
        except InvalidSignature:
            return False

        return True

    def __validate_transactions(self, transactions):
        for transaction in transactions:
            sender_account_balance = self._accounts.get(
                transaction["message"]["sender"]).balance

            if transaction["message"]["value"] > sender_account_balance:
                return False
        return True

    def __process_transactions(self, transactions):
        # For all transactions, first check that the sender has enough balance.
        # Return False otherwise
        if not self.__validate_transactions(transactions):
            return False

        # Appropriately transfer value from the sender to the receiver
        for transaction in transactions:
            sending_amount = transaction["message"]["value"]

            self._accounts.get(
                transaction["message"]["receiver"]).increase_balance(sending_amount)
            self._accounts.get(
                transaction["message"]["sender"]).decrease_balance(sending_amount)

        return True

    # Creates a new block and appends to the chain
    # Also clears the pending transactions as they are part of the new block now
    def create_new_block(self):
        new_block = Block(len(self._chain), self._pending_transactions, self._chain[-1].block_hash, self._hash_target)
        if self.__process_transactions(self._pending_transactions):
            self._chain.append(new_block)
            self._pending_transactions = []
            return new_block
        else:
            return False

    # Simple transaction with just one sender, one receiver, and one value
    # Created by the account and sent to the blockchain instance
    def add_transaction(self, transaction):
        if self.__validate_transaction(transaction):
            self._pending_transactions.append(transaction)
            return True
        else:
            print(f'ERROR: Transaction: {transaction} failed signature validation')
            return False

    def __validate_chain_hash_integrity(self):
        # Run through the whole blockchain and ensure that previous hash is actually the hash of the previous block
        # Return False otherwise
        prev_block_hash = self._chain[0]._block_hash
        for block in self._chain[1:]:
            if prev_block_hash != block._previous_block_hash:
                return False
            else:
                prev_block_hash = block._block_hash

        return True

    def __validate_block_hash_target(self):
        # Run through the whole blockchain and ensure that block hash meets hash target criteria, and is the actual hash of the block
        # Return False otherwise
        for block in self._chain[1:]:
            if self._hash_target < block._block_hash:
                return False

        return True

    def __validate_complete_account_balances(self):
        # Run through the whole blockchain and ensure that balances never become negative from any transaction
        # Return False otherwise
        account_balances = {}
        for block in self._chain[1:]:
            if not self.__validate_transaction_of_block(block, account_balances):
                return False
        return True

    # Validates account balances across transactions for block starting with initial balance
    # and ensures that blanace never goes less than zero
    def __validate_transaction_of_block(self, block, account_balances):
        for transaction in block.transactions:
            sending_amount = transaction["message"]["value"]
            sender_account_id = transaction["message"]["sender"]
            receiver_account_id = transaction["message"]["receiver"]
            # If this is the first transaction for sender account initialize the balance with initial_balances
            if not sender_account_id in account_balances:
                account_balances[sender_account_id] = {}
                account_balances[sender_account_id]["balance"] = self._accounts.get(
                    sender_account_id).initial_balance
            # If this is the first transaction for receiver account initialize the balance with initial_balances
            if not receiver_account_id in account_balances:
                account_balances[receiver_account_id] = {}
                account_balances[receiver_account_id]["balance"] = self._accounts.get(
                    receiver_account_id).initial_balance

            # Increment and decrement the sender and receiver accounts appropriatly
            account_balances[sender_account_id]["balance"] = account_balances[
                sender_account_id]["balance"] - sending_amount
            account_balances[receiver_account_id]["balance"] = account_balances[
                receiver_account_id]["balance"] + sending_amount

            # Now validate if the sender balance gone below zero after transaction
            if account_balances[sender_account_id]["balance"] < 0:
                return False
        return True

    # Blockchain validation function
    # Runs through the whole blockchain and applies appropriate validations
    def validate_blockchain(self):
        # Call __validate_chain_hash_integrity and implement that method. Return False if check fails
        # Call __validate_block_hash_target and implement that method. Return False if check fails
        # Call __validate_complete_account_balances and implement that method. Return False if check fails
        return self.__validate_chain_hash_integrity() and self.__validate_block_hash_target() and self.__validate_complete_account_balances()

    def add_account(self, account):
        self._accounts[account.id] = account

    def get_account_balances(self):
        return [{'id': account.id, 'balance': account.balance} for account in self._accounts.values()]



