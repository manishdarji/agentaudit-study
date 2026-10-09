"""M4: on-chain anchoring through a tiny Vyper contract.

Works against a local simulated chain (tests, gas measurement) or a real RPC endpoint such as
Base Sepolia (set rpc_url and private_key). Gas for the same contract is the same on a local EVM,
so local runs give the execution-gas figure; latency and L2 data fees must come from the real testnet.
"""
import functools
import time

import vyper
from web3 import Web3

from ..events import Anchor
from . import MissingDependency, Receipt

CONTRACT_SRC = """# pragma version ^0.4.0

struct Rec:
    length: uint256
    head: bytes32

records: public(HashMap[uint256, Rec])
count: public(uint256)
owner: public(address)

event Anchored:
    epoch: indexed(uint256)
    length: uint256
    head: bytes32

@deploy
def __init__():
    self.owner = msg.sender

@external
def anchor(length: uint256, head: bytes32):
    assert msg.sender == self.owner
    epoch: uint256 = self.count
    self.records[epoch] = Rec(length=length, head=head)
    self.count = epoch + 1
    log Anchored(epoch=epoch, length=length, head=head)
"""


@functools.lru_cache(maxsize=1)
def compile_contract():
    out = vyper.compile_code(CONTRACT_SRC, output_formats=["abi", "bytecode"])
    return out["abi"], out["bytecode"]


def local_chain() -> Web3:
    """In-memory test chain with funded accounts and automatic mining."""
    try:
        import eth.chains.base  # noqa: F401  (module provided by the py-evm package)
    except ImportError:
        raise MissingDependency(
            "py-evm is not installed, so the local test chain cannot run. "
            'Install it with:  pip install "eth-tester[py-evm]"'
        )
    from web3 import EthereumTesterProvider

    return Web3(EthereumTesterProvider())


def rpc_chain(rpc_url: str) -> Web3:
    """Connect to a real network, e.g. https://sepolia.base.org for Base Sepolia."""
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"cannot reach {rpc_url}")
    return w3


class ChainAnchorer:
    name = "M4-chain"

    def __init__(self, w3: Web3, private_key: str = None, contract_address: str = None):
        self.w3, self.pk = w3, private_key
        abi, bytecode = compile_contract()
        if private_key:
            self.account = w3.eth.account.from_key(private_key).address
        else:
            self.account = w3.eth.accounts[0]
        self.deploy_gas = None
        if contract_address:
            self.contract = w3.eth.contract(address=contract_address, abi=abi)
        else:
            factory = w3.eth.contract(abi=abi, bytecode=bytecode)
            receipt = self._send(factory.constructor())
            self.deploy_gas = receipt["gasUsed"]
            self.contract = w3.eth.contract(address=receipt["contractAddress"], abi=abi)

    def _send(self, fn):
        if self.pk:
            tx = fn.build_transaction({
                "from": self.account,
                "nonce": self.w3.eth.get_transaction_count(self.account),
            })
            signed = self.w3.eth.account.sign_transaction(tx, self.pk)
            h = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        else:
            h = fn.transact({"from": self.account})
        return self.w3.eth.wait_for_transaction_receipt(h)

    def publish(self, anchor: Anchor) -> Receipt:
        t0 = time.perf_counter()
        receipt = self._send(self.contract.functions.anchor(anchor.length, bytes.fromhex(anchor.head_hash)))
        return Receipt(self.name, time.perf_counter() - t0, {"gas": receipt["gasUsed"]},
                       ref=receipt["transactionHash"].hex())

    def published(self) -> list:
        n = self.contract.functions.count().call()
        out = []
        for i in range(n):
            length, head = self.contract.functions.records(i).call()
            out.append(Anchor(length=length, head_hash=head.hex()))
        return out
