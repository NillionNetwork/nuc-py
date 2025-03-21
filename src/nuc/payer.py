"""
Nilchain payer.
"""

import logging
from cosmpy.aerial.tx import Transaction
from cosmpy.aerial.wallet import Address, LocalWallet
from cosmpy.crypto.keypairs import PrivateKey as NilchainPrivateKey
from cosmpy.aerial.client import (
    LedgerClient,
    NetworkConfig,
    prepare_and_broadcast_basic_transaction,
)

# pylint: disable=E0611
from .proto.tx_pb2 import MsgPayFor, Amount

logger = logging.getLogger(__name__)


DEFAULT_QUERY_TIMEOUT_SECONDS = 30
DEFAULT_QUERY_POLL_SECONDS = 1


class Payer:
    """
    A payer that allows making payments on nilchain.
    """

    def __init__(
        self,
        wallet_private_key: NilchainPrivateKey,
        chain_id: str,
        grpc_endpoint: str,
        gas_limit: int,
        query_timeout_seconds: int = DEFAULT_QUERY_TIMEOUT_SECONDS,
        query_poll_seconds: int = DEFAULT_QUERY_POLL_SECONDS,
    ) -> None:
        self.wallet = LocalWallet(wallet_private_key, "nillion")
        self.gas_limit = gas_limit
        payments_config = NetworkConfig(
            chain_id=chain_id,
            url=f"grpc+{grpc_endpoint}/",
            fee_minimum_gas_price=0,
            fee_denomination="unil",
            staking_denomination="unil",
            faucet_url=None,
        )
        self.client = LedgerClient(
            payments_config,
            query_interval_secs=query_poll_seconds,
            query_timeout_secs=query_timeout_seconds,
        )

    def pay(self, resource: bytes, amount_unil: int) -> str:
        """
        Perform a `MsgPayFor` payment for the given resource.

        Arguments
        ---------

        resource
            The resource to use in the transaction.
        amount_unil
            The amount of unil to send in the payment.
        """

        transaction = Transaction()
        message = MsgPayFor(
            resource=resource,
            from_address=str(Address(self.wallet.public_key(), "nillion")),
            amount=[Amount(denom="unil", amount=str(amount_unil))],
        )
        transaction.add_message(message)

        submitted_transaction = prepare_and_broadcast_basic_transaction(
            self.client, transaction, self.wallet, gas_limit=self.gas_limit
        )

        tx_hash = submitted_transaction.tx_hash
        logger.info("Waiting for transaction %s to be committed", tx_hash)
        submitted_transaction.wait_to_complete()
        return tx_hash
