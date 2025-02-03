from web3 import Web3
import os
import dotenv

infura_key = os.environ.get("INFURA_KEY", "")
# RPC URL of the blockchain (use Infura, Alchemy, or your own node)
RPC_URL = f"https://base-sepolia.infura.io/v3/{infura_key}"
web3 = Web3(Web3.HTTPProvider(RPC_URL))

# ERC-20 contract address
TOKEN_ADDRESS = os.environ.get("TOKEN_ADDRESS", "")

# ERC-20 ABI (Minimal ABI for balance and transfer)
ERC20_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "name",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function",
    },
]

# Connect to the contract
contract = web3.eth.contract(address=TOKEN_ADDRESS, abi=ERC20_ABI)


# Function to get token details
def get_token_details():
    name = contract.functions.name().call()
    symbol = contract.functions.symbol().call()
    decimals = contract.functions.decimals().call()
    print(f"Token Name: {name}\nSymbol: {symbol}\nDecimals: {decimals}")


# Function to check balance
def get_balance(account):
    balance = contract.functions.balanceOf(account).call()
    decimals = contract.functions.decimals().call()
    return balance / (10**decimals)  # Convert from smallest unit


# Function to send tokens
def send_tokens(private_key, to_address, amount):
    account = web3.eth.account.from_key(private_key)
    nonce = web3.eth.get_transaction_count(account.address)
    decimals = contract.functions.decimals().call()
    value = int(amount * (10**decimals))  # Convert to smallest unit

    tx = contract.functions.transfer(to_address, value).build_transaction(
        {
            "from": account.address,
            "gas": 200000,
            "gasPrice": web3.to_wei("1", "gwei"),
            "nonce": nonce,
        }
    )

    signed_tx = web3.eth.account.sign_transaction(tx, private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
    return web3.to_hex(tx_hash)


# Example Usage
if __name__ == "__main__":
    my_address = "0x9a382e06F97384d40A5cfB354485e343419afddf"
    private_key = os.environ.get("PRIVATE_KEY", "")
    recipient_address = "0x351Ac7e94d0e4f2bBE5DAC2d469B91e7725f8078"

    get_token_details()
    print(f"Balance: {get_balance(my_address)} tokens")

    # Uncomment to send tokens
    tx_hash = send_tokens(private_key, recipient_address, 1.5)  # Sending 1.5 tokens
    print(f"Transaction Hash: {tx_hash}")

    get_token_details()
    print(f"Balance: {get_balance(my_address)} tokens")
