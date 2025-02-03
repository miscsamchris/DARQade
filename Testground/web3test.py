import json
from web3 import Web3
from solcx import compile_source, install_solc
import os
import dotenv

# Load environment variables
dotenv.load_dotenv()
# Install Solidity compiler
install_solc("0.8.0")

# Read the Solidity contract
with open("ERC20Token.sol", "r") as file:
    contract_source_code = file.read()

# Compile the contract
compiled_sol = compile_source(contract_source_code, solc_version="0.8.0")
contract_interface = compiled_sol[next(iter(compiled_sol))]
infura_key = os.environ.get("INFURA_KEY", "")

# Web3 connection (use Infura, Alchemy, or your own node)
RPC_URL = f"https://base-sepolia.infura.io/v3/{infura_key}"
web3 = Web3(Web3.HTTPProvider(RPC_URL))

# Wallet details
private_key = os.environ.get("PRIVATE_KEY", "")

account = web3.eth.account.from_key(private_key)
web3.eth.default_account = account.address

# Deploy contract
ERC20 = web3.eth.contract(
    abi=contract_interface["abi"], bytecode=contract_interface["bin"]
)

# Set constructor parameters
name = "MyToken"
symbol = "MTK"
decimals = 18
total_supply = 1000000  # 1 Million Tokens

# Build transaction
transaction = ERC20.constructor(name, symbol, decimals, total_supply).build_transaction(
    {
        "from": account.address,
        "gas": 2000000,
        "gasPrice": web3.to_wei("1", "gwei"),
        "nonce": web3.eth.get_transaction_count(account.address),
    }
)

# Sign and send transaction
signed_txn = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

# Output contract address
print(f"Contract Deployed at: {tx_receipt.contractAddress}")
