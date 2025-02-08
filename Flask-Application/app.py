from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    make_response,
)
import os
import uuid
import requests
from web3 import Web3
from solcx import compile_source, install_solc
import math
import dotenv, os
import utils
from werkzeug.utils import secure_filename
import json, qrcode, io
from cdp_langchain.tools import CdpTool
from pydantic import BaseModel, Field
from typing import Union
from datetime import datetime

# Import necessary classes from your LangChain/CDP Agentkit setup.
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

from cdp_langchain.agent_toolkits import CdpToolkit
from cdp_langchain.utils import CdpAgentkitWrapper
import cloudinary
import cloudinary.uploader
import cloudinary.api

# Global dictionary to store conversation sessions.
dotenv.load_dotenv()
install_solc("0.8.0")
# Blockchain Connection
INFURA_KEY = os.environ.get("INFURA_KEY", "YOUR_INFURA_API_KEY")
RPC_URL = f"https://base-sepolia.infura.io/v3/{INFURA_KEY}"
web3 = Web3(Web3.HTTPProvider(RPC_URL))
private_key = os.getenv("PRIVATE_KEY", "PrivateKey")  # Store securely!
admin = web3.eth.account.from_key(private_key)
web3.eth.default_account = admin.address

# Blockscout API URL
BLOCKSCOUT_API_URL = "https://base.blockscout.com/api/v2/search/quick?q="

BLOCKSCOUT_API_URL_GET_BASENAME = "https://base.blockscout.com/api/v2/tokens/0x03c4738Ee98aE44591e1A4A4F3CaB6641d95DD9a/instances?holder_address_hash={}"
# ERC-20 Solidity Contract (Without OpenZeppelin)
ERC20_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ERC20Token {
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory _name, string memory _symbol, uint8 _decimals, uint256 _totalSupply) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;
        totalSupply = _totalSupply * 10 ** uint256(_decimals);
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value, "Insufficient balance");
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value, "Insufficient balance");
        require(allowance[_from][msg.sender] >= _value, "Allowance exceeded");
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
}
"""


compiled_sol = compile_source(ERC20_SOURCE, solc_version="0.8.0")
contract_interface = compiled_sol[next(iter(compiled_sol))]

app = Flask(__name__)


game_test_sessions = {}

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)


@app.route("/gamedev/signup", methods=["POST"])
def gamedev_signup():
    data = request.json
    email = data["email"]
    company_name = data["company_name"]
    password = data["password"]

    # Optional fields with default values
    website = data.get("website", "")
    description = data.get("description", "")
    # Check if developer already exists
    utils.token_gen.update_config()
    if utils.login_gamedev(email, password) != {}:
        return jsonify({"error": "Game developer already exists"}), 400

    # Generate Ethereum Wallet for the game developer
    account = web3.eth.account.create()
    wallet_address = account.address
    private_key = account.key.hex()
    value = web3.to_wei(0.01, "ether")
    gas_price = web3.eth.gas_price
    print(f"Gas Price: {gas_price}")
    print(f"Value: {value}")
    # Build transaction
    transaction = {
        "to": wallet_address,
        "value": value,
        "gas": 21000,
        "gasPrice": web3.eth.gas_price,
        "nonce": web3.eth.get_transaction_count(admin.address),
        "chainId": web3.eth.chain_id,
    }
    account.key
    # Sign and send transaction
    signed_txn = web3.eth.account.sign_transaction(transaction, admin.key.hex())
    tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
    # Save game developer details in MongoDB
    gamedev_id = str(uuid.uuid4())
    utils.token_gen.update_config()
    utils.upload_gamedev(
        gamedev_id,
        email,
        company_name,
        password,
        website,
        description,
        wallet_address,
        private_key,
        False,
        0,
        True,
    )
    return (
        jsonify(
            {
                "message": "Game developer account created successfully",
                "uuid": gamedev_id,
                "wallet_address": wallet_address,
            }
        ),
        201,
    )


def get_unique_basenames(wallet_addresses):
    unique_basenames = set()
    for address in wallet_addresses:
        try:
            response = requests.get(BLOCKSCOUT_API_URL_GET_BASENAME.format(address))
            if response.status_code == 200:
                data = response.json()
                for item in data.get("items", []):
                    basename = item.get("metadata", {}).get("name")
                    if basename:
                        unique_basenames.add(basename)
            else:
                print(
                    f"Failed to fetch data for {address}, Status Code: {response.status_code}"
                )
        except Exception as e:
            print(f"Error fetching data for {address}: {e}")
    return list(unique_basenames)


def get_wallet_from_uuid(myuuid):
    # Fetch the user from the database
    utils.token_gen.update_config()

    user = utils.get_user_by_id(myuuid)
    if not user:
        return None, "User not found"

    # Check if the user has a private key
    if "Private Key" not in user:
        return None, "Private key not found for user"

    # Get the private key from the user object
    private_key = user["Private Key"]

    # Create a web3.eth.Account object using the private key
    try:
        account = Web3().eth.account.from_key(private_key)
        return account, None
    except Exception as e:
        return None, f"Failed to create wallet: {str(e)}"


class EthBalanceInput(BaseModel):
    wallet_address: str = Field(..., description="The Ethereum wallet address.")


class PayGameFeeInput(BaseModel):
    user_uuid: str = Field(..., description="The user's UUID.")
    amount: float = Field(..., description="The amount of ETH to send (in ether).")
    recipient_wallet: str = Field(
        ..., description="The wallet address that will receive the game fee."
    )
    game_id: str = Field(..., description="The Game's UUID.")


class TransferTokenInput(BaseModel):
    token_address: str = Field(..., description="The ERC20 token contract address.")
    user_uuid: str = Field(
        ..., description="The user ID of the destination wallet address."
    )
    amount: float = Field(
        ..., description="The amount of tokens to transfer (in human-readable units)."
    )
    gamedev_uuid: str = Field(
        ..., description="The gamedev user's UUID to look up their private key."
    )


########################################
# 6. ETH Balance Tool
########################################
def eth_balance_tool(wallet_address: str) -> str:
    """
    Get the ETH balance of a given wallet.

    Args:
        wallet_address: The Ethereum wallet address.

    Returns:
        A JSON string with the wallet address and its ETH balance.
    """
    try:
        balance_wei = web3.eth.get_balance(wallet_address)
        balance_eth = web3.from_wei(balance_wei, "ether")
        result = {"wallet_address": wallet_address, "eth_balance": float(balance_eth)}
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"error": str(e)})


########################################
# 8. Pay Game Fee Tool
########################################
def pay_game_fee_tool(
    user_uuid: str, amount: float, recipient_wallet: str, game_id: str
) -> str:
    """
    Pay a game fee by transferring ETH from a user's account to a specified recipient wallet.

    Args:
        user_uuid: The user's UUID.
        amount: The amount of ETH to send (in ether).
        recipient_wallet: The wallet address that will receive the game fee.
        game_id: The Games's UUID.

    Returns:
        A JSON string with a success message and the transaction hash.
    """
    # Retrieve the user's account details using their UUID.
    # Assumes get_wallet_from_uuid is defined elsewhere and returns (account, message)
    myacc, message = get_wallet_from_uuid(user_uuid)
    if not myacc:
        return json.dumps({"error": message})

    # Convert the fee amount from ether to Wei.
    value = web3.to_wei(amount, "ether")
    gas_price = web3.eth.gas_price

    # Build the transaction: the fee is sent to the provided recipient wallet.
    transaction = {
        "to": recipient_wallet,
        "value": value,
        "gas": 21000,
        "gasPrice": gas_price,
        "nonce": web3.eth.get_transaction_count(myacc.address),
        "chainId": web3.eth.chain_id,
    }

    # Sign and send the transaction.
    signed_txn = web3.eth.account.sign_transaction(transaction, myacc.key.hex())
    tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)

    utils.token_gen.update_config()
    gamedev = utils.get_gamedev_by_wallet(recipient_wallet)
    if gamedev != {}:
        utils.token_gen.update_config()
        utils.update_gamedev(
            gamedev_id=gamedev["_id"],
            email=gamedev["Email"],
            company_name=gamedev["Company Name"],
            password=gamedev["Password"],
            website=gamedev["Website"],
            description=gamedev["Description"],
            wallet_address=gamedev["Wallet Address"],
            private_key=gamedev["Private Key"],
            token=gamedev["Token"],
            total_revenue=gamedev["Total Revenue"] + amount,
            active_status=gamedev["Active Status"],
            verified=gamedev["Verified"],
        )
    utils.token_gen.update_config()
    game = utils.get_game(game_id)
    if game != {}:
        utils.token_gen.update_config()
        utils.update_game(
            game_id,
            title=game["title"],
            description=game["description"],
            prompt=game["prompt"],
            winning_condition=game["winning_condition"],
            cost_in_eth=game["cost_in_eth"],
            reward_in_tokens=game["reward_in_tokens"],
            card_type=game["game_type"],
            revenue=game["revenue"] + amount,
            players=game["players"] + 1,
            imagePath=game["imagePath"],
            status=game["status"],
        )
    return json.dumps(
        {"message": "Game fee paid", "transaction_hash": web3.to_hex(tx_hash)}
    )


def transfer_token_tool(
    token_address: str, user_uuid: str, amount: float, gamedev_uuid: str
) -> str:
    """
    Transfer tokens from a gamedev's wallet to another address.

    Args:
        token_address (str): The ERC20 token contract address.
        user_uuid (str): The user id of the destination wallet address.
        amount (float): The amount of tokens to transfer (in human-readable units).
        gamedev_uuid (str): The gamedev user's UUID to look up their private key.

    Returns:
        A JSON string containing a success message and the transaction hash, or an error message.
    """
    # Retrieve the gamedev's details from the database
    print(gamedev_uuid)
    utils.token_gen.update_config()
    gamedev = utils.get_gamedev_by_id(gamedev_uuid)
    if not gamedev:
        return json.dumps({"error": "Game developer not found"})

    # Create an account instance from the private key
    account = web3.eth.account.from_key(gamedev["Private Key"])
    myacc, message = get_wallet_from_uuid(user_uuid)

    # Minimal ERC20 ABI for transferring tokens and querying decimals
    ERC20_ABI = [
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
        {
            "constant": True,
            "inputs": [],
            "name": "decimals",
            "outputs": [{"name": "", "type": "uint8"}],
            "type": "function",
        },
    ]

    # Initialize the token contract
    contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)

    # Retrieve decimals and convert the human-readable amount to the smallest unit
    decimals = contract.functions.decimals().call()
    value = int(amount * (10**decimals))

    # Build the transaction
    transaction = contract.functions.transfer(myacc.address, value).build_transaction(
        {
            "from": account.address,
            "gas": 100000,
            "gasPrice": web3.to_wei("1", "gwei"),
            "nonce": web3.eth.get_transaction_count(account.address),
        }
    )

    # Sign and send the transaction
    signed_txn = web3.eth.account.sign_transaction(transaction, account.key.hex())
    tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)

    return json.dumps(
        {"message": "Transfer Successful", "transaction_hash": web3.to_hex(tx_hash)}
    )


@app.route("/gamedev/login", methods=["POST"])
def gamedev_login():
    data = request.json
    print(data)
    email = data["email"]
    password = data["password"]
    utils.token_gen.update_config()
    gamedev = utils.login_gamedev(email, password)

    if gamedev == {}:
        return jsonify({"error": "Invalid email or password"}), 401
    utils.token_gen.update_config()
    token = utils.get_token_by_gamedev_wallet(gamedev["Wallet Address"])
    if token == {}:
        return (
            jsonify(
                {
                    "message": "Login successful",
                    "uuid": gamedev["_id"],
                    "company_name": gamedev["Company Name"],
                    "wallet_address": gamedev["Wallet Address"],
                    "hastoken": "false",
                }
            ),
            200,
        )
    else:
        return (
            jsonify(
                {
                    "message": "Login successful",
                    "uuid": gamedev["_id"],
                    "company_name": gamedev["Company Name"],
                    "wallet_address": gamedev["Wallet Address"],
                    "hastoken": "true",
                }
            ),
            200,
        )


@app.route("/create_token", methods=["POST"])
def create_token():
    data = request.json
    name = data["name"]
    symbol = data["symbol"]
    decimals = int(data["decimals"])
    total_supply = int(data["total_supply"])
    myuuid = data["uuid"]
    utils.token_gen.update_config()
    gamedev = utils.get_gamedev_by_id(myuuid)
    if gamedev == {}:
        return jsonify({"error": "Invalid email or password"}), 401

    account = web3.eth.account.from_key(gamedev["Private Key"])
    ERC20 = web3.eth.contract(
        abi=contract_interface["abi"], bytecode=contract_interface["bin"]
    )

    # Build transaction
    transaction = ERC20.constructor(
        name, symbol, decimals, total_supply
    ).build_transaction(
        {
            "from": account.address,
            "gas": 1000000,
            "gasPrice": web3.to_wei("1", "gwei"),
            "nonce": web3.eth.get_transaction_count(account.address),
        }
    )

    # Sign and send
    signed_txn = web3.eth.account.sign_transaction(transaction, account.key.hex())
    tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    contract_address = tx_receipt.contractAddress

    utils.token_gen.update_config()
    utils.upload_token(
        name,
        symbol,
        decimals,
        str(total_supply),
        str(contract_address),
        str(account.address),
    )

    utils.token_gen.update_config()
    utils.update_gamedev(
        myuuid,
        private_key=gamedev["Private Key"],
        company_name=gamedev["Company Name"],
        email=gamedev["Email"],
        website=gamedev["Website"],
        description=gamedev["Description"],
        wallet_address=gamedev["Wallet Address"],
        token=str(contract_address),
        password=gamedev["Password"],
        total_revenue=gamedev["Total Revenue"],
        active_status=gamedev["Active Status"],
        verified=False,
    )
    return (
        jsonify({"message": "Token Created", "contract_address": contract_address}),
        201,
    )


@app.route("/gamedev/<uuid>/games", methods=["GET"])
def get_games(uuid):
    utils.token_gen.update_config()
    games = utils.get_games_by_gamedev(uuid)
    if games == {}:
        return jsonify({"error": "Game developer not found"}), 404
    utils.token_gen.update_config()
    gamedev = utils.get_gamedev_by_id(uuid)
    if gamedev == {}:
        revenue = 0.0
    else:
        revenue = gamedev["Total Revenue"]
    return jsonify({"Games": games["games"], "Revenue": revenue}), 200


@app.route("/arcade_games", methods=["GET"])
def get_arcade_games():
    utils.token_gen.update_config()
    games = utils.get_games_by_status("Released")
    if games == {}:
        return jsonify({"error": "Game developer not found"}), 404
    GAMES = []
    for game in games["games"]:
        print(game)
        utils.token_gen.update_config()
        gamedev = utils.get_gamedev_by_id(game["game_developer"])
        token = utils.get_token_by_gamedev_wallet(gamedev["Wallet Address"])
        game["token"] = f" {token['name']} ({token['symbol']})"
        game["publisher"] = gamedev["Company Name"]
        GAMES.append(game)
    return jsonify(GAMES), 200


@app.route("/gamedev/create_game", methods=["POST"])
def create_game():
    data = request.form  # Use request.form for form data
    print(data)
    myuuid = data.get("uuid")

    # Get the file from the form (make sure the file input's name attribute is "Logo")
    logo_file = request.files.get("Logo")
    logo_filename = None
    url = ""
    if logo_file:
        # Secure the filename
        upload_result = cloudinary.uploader.upload(logo_file)
        url = upload_result["secure_url"]
    # Optionally, you could pass the logo_filename to your upload_game function if needed.
    utils.token_gen.update_config()
    utils.upload_game(
        title=data.get("game_title"),
        description=data.get("game_description"),
        prompt=data.get("prompt"),
        winning_condition=data.get("winning_condition"),
        cost_in_eth=float(data.get("cost_in_eth")),
        reward_in_tokens=float(data.get("reward_in_tokens")),
        card_type=int(data.get("card_type", "prompt")),
        developer_id=myuuid,
        imagePath=url,
    )

    return redirect(url_for("dash"))  # Redirect to the dashboard page


@app.route("/release_game", methods=["POST"])
def release_game():
    data = request.json
    status = data["status"]
    game_id = data["game_id"]

    utils.token_gen.update_config()
    game = utils.get_game(game_id)
    if game == {}:
        return jsonify({"error": "Game not found."}), 404
    utils.token_gen.update_config()
    utils.update_game(
        game_id,
        game["title"],
        game["description"],
        game["prompt"],
        game["winning_condition"],
        game["cost_in_eth"],
        game["reward_in_tokens"],
        game["game_type"],
        game["revenue"],
        game["players"],
        game["imagePath"],
        status,
    )
    return (
        jsonify(
            {
                "game_id": game_id,
                "message": "Game Release.",
            }
        ),
        201,
    )


@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    email = data["email"]
    basename = data["basename"]
    password = data["password"]  # Plain password for encryption

    # Generate Ethereum Wallet
    account = web3.eth.account.create()
    wallet_address = account.address
    private_key = account.key.hex()  # Store securely in production!

    utils.token_gen.update_config()
    # Store encrypted user data across nodes
    success = utils.upload_user(email, basename, password, wallet_address, private_key)

    if not success:
        return jsonify({"error": "Failed to create user"}), 500

    return (
        jsonify(
            {"message": "User created successfully", "wallet_address": wallet_address}
        ),
        201,
    )


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data["email"]
    password = data["password"]  # Plain password for comparison

    utils.token_gen.update_config()
    user = utils.login_user(email, password)

    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    return (
        jsonify({"message": "Login successful", "uuid": user.get("uuid", "N/A")}),
        200,
    )


@app.route("/Gamedev")
def gamedev_home():
    return render_template("index.html")


@app.route("/")
def home():
    return render_template("user_index.html")


@app.route("/DARQade")
def arcade():
    return render_template("arcade.html")


@app.route("/test")
def test():
    return render_template("test.html")


@app.route("/Gamedev/Dashboard")
def dash():
    return render_template("dashboard.html")


def initialize_agent():
    """
    Initialize the agent with CDP Agentkit.
    Returns:
        agent_executor: The ReAct agent instance.
        config: A configuration dictionary.
    """
    # Initialize the LLM.
    llm = ChatOpenAI(model="gpt-4o")
    wallet_data_file = "wallet_data.txt"
    wallet_data = None
    if os.path.exists(wallet_data_file):
        with open(wallet_data_file) as f:
            wallet_data = f.read()

    # Configure the CDP Agentkit.
    values = {}
    if wallet_data is not None:
        values = {"cdp_wallet_data": wallet_data}

    agentkit = CdpAgentkitWrapper(**values)

    # Persist the agent's wallet data.
    wallet_data = agentkit.export_wallet()
    with open(wallet_data_file, "w") as f:
        f.write(wallet_data)

    # Initialize the CDP toolkit and select tools.
    cdp_toolkit = CdpToolkit.from_cdp_agentkit_wrapper(agentkit)
    tools = cdp_toolkit.get_tools()
    all_tools = []
    eth_balance_tool_instance = CdpTool(
        name="eth_balance",
        func=eth_balance_tool,
        description=(
            "Retrieve the ETH balance of a wallet. "
            "Input parameter: wallet_address (str)."
        ),
        args_schema=PayGameFeeInput,
        cdp_agentkit_wrapper=agentkit,
    )
    pay_game_fee_tool_instance = CdpTool(
        name="pay_game_fee",
        func=pay_game_fee_tool,
        description=(
            "Pay a game fee by transferring ETH from a user's account to a specified wallet. "
            "Input parameters: user_uuid (str), amount (float, in ether), recipient_wallet (str), game_id (str)."
        ),
        args_schema=PayGameFeeInput,
        cdp_agentkit_wrapper=agentkit,
    )
    transfer_token_tool_instance = CdpTool(
        name="transfer_token",
        func=transfer_token_tool,
        description=(
            "Transfer tokens from a gamedev's wallet to another address. "
            "Input parameters: token_address (str), user_uuid (str), amount (float), gamedev_uuid (str)."
        ),
        args_schema=TransferTokenInput,
        cdp_agentkit_wrapper=agentkit,
    )
    for tool in tools:
        # For this example we only add the "deploy_token" tool.
        if tool.name == "deploy_token":
            all_tools.append(tool)
    all_tools.append(pay_game_fee_tool_instance)
    all_tools.append(eth_balance_tool_instance)
    all_tools.append(transfer_token_tool_instance)
    # Set up an in-memory buffer for conversation history.
    memory = MemorySaver()
    config = {"configurable": {"thread_id": "CDP Agentkit Chatbot Example!"}}

    # Create the ReAct agent using the LLM, tools, and memory.
    agent_executor = create_react_agent(
        llm,
        tools=all_tools,
        checkpointer=memory,
        state_modifier=(
            "You are a helpful agent that can interact onchain using the Coinbase Developer Platform AgentKit. "
            "You are empowered to interact onchain using your tools. If you ever need funds, you can request "
            "them from the faucet if you are on network ID 'base-sepolia'. If not, you can provide your wallet "
            "details and request funds from the user. Before executing your first action, get the wallet details "
            "to see what network you're on. If there is a 5XX (internal) HTTP error code, ask the user to try "
            "again later. If someone asks you to do something you can't do with your currently available tools, "
            "you must say so, and encourage them to implement it themselves using the CDP SDK + Agentkit, "
            "recommending they go to docs.cdp.coinbase.com for more information. Be concise and helpful with your "
            "responses. Refrain from restating your tools' descriptions unless it is explicitly requested. Do not use Any markdown notation like ** in the Response."
        ),
    )
    return agent_executor, config


def initialize_agent_test():
    """
    Initialize the agent with CDP Agentkit using Nillion AI.
    Returns:
        agent_executor: The ReAct agent instance.
        config: A configuration dictionary.
    """
    # Initialize the LLM.

    llm = ChatOpenAI(
        model="meta-llama/Llama-3.1-8B-Instruct",
        base_url="https://nilai-a779.nillion.network/v1",
        default_headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer Nillion2025",
        },
    )
    wallet_data_file = "wallet_data.txt"
    wallet_data = None
    if os.path.exists(wallet_data_file):
        with open(wallet_data_file) as f:
            wallet_data = f.read()

    # Configure the CDP Agentkit.
    values = {}
    if wallet_data is not None:
        values = {"cdp_wallet_data": wallet_data}

    agentkit = CdpAgentkitWrapper(**values)

    # Persist the agent's wallet data.
    wallet_data = agentkit.export_wallet()
    with open(wallet_data_file, "w") as f:
        f.write(wallet_data)

    # Initialize the CDP toolkit and select tools.
    cdp_toolkit = CdpToolkit.from_cdp_agentkit_wrapper(agentkit)
    tools = cdp_toolkit.get_tools()
    all_tools = []

    # Set up an in-memory buffer for conversation history.
    memory = MemorySaver()
    config = {"configurable": {"thread_id": "CDP Agentkit Chatbot Example!"}}

    # Create the ReAct agent using the LLM, tools, and memory.
    agent_executor = create_react_agent(
        llm,
        tools=all_tools,
        checkpointer=memory,
        state_modifier=(
            "You are a helpful agent that can interact onchain using the Coinbase Developer Platform AgentKit. "
            "You are empowered to interact onchain using your tools. If you ever need funds, you can request "
            "them from the faucet if you are on network ID 'base-sepolia'. If not, you can provide your wallet "
            "details and request funds from the user. Before executing your first action, get the wallet details "
            "to see what network you're on. If there is a 5XX (internal) HTTP error code, ask the user to try "
            "again later. If someone asks you to do something you can't do with your currently available tools, "
            "you must say so, and encourage them to implement it themselves using the CDP SDK + Agentkit, "
            "recommending they go to docs.cdp.coinbase.com for more information. Be concise and helpful with your "
            "responses. Refrain from restating your tools' descriptions unless it is explicitly requested. Do not use Any markdown notation like ** in the Response."
        ),
    )
    return agent_executor, config


@app.route("/start_game_test", methods=["POST"])
def start_game_test():
    """
    Starts a new game test session.
    Expects JSON input with a "prompt" key containing the initial prompt.
    Returns a unique session_id along with the agent’s first response.
    """
    data = request.json
    game_id = data.get("game_id", "")
    user_uuid = data.get("user_uuid", "NA")
    print(data)
    utils.token_gen.update_config()
    game = utils.get_game(game_id)
    if game == {}:
        return jsonify({"error": "Game not found."}), 404
    prompt = game.get("prompt")
    utils.token_gen.update_config()
    gamedev = utils.get_gamedev_by_id(game["game_developer"])
    if gamedev == {}:
        return jsonify({"error": "GameDev not found."}), 404

    prompt_suffix = f"""\n Focus on the Game Prompts and on the Interactions. \n\nThe Winning Condition:\n{game.get("winning_condition")} """
    # Initialize a new agent instance.
    agent_executor, config = initialize_agent_test()

    # Prime the conversation with the initial prompt.
    initial_response = ""
    for chunk in agent_executor.stream(
        {"messages": [HumanMessage(content=prompt + prompt_suffix)]}, config
    ):
        if "agent" in chunk:
            # Capture the agent's response (the last such chunk will be used).
            initial_response = chunk["agent"]["messages"][0].content

    # Generate a unique session ID and store the agent instance and config.
    session_id = str(uuid.uuid4())
    game_test_sessions[session_id] = (agent_executor, config)

    return (
        jsonify(
            {
                "session_id": session_id,
                "message": "Game test session started.",
                "initial_response": initial_response,
            }
        ),
        201,
    )


@app.route("/start_game", methods=["POST"])
def start_game():
    """
    Starts a new game test session.
    Expects JSON input with a "prompt" key containing the initial prompt.
    Returns a unique session_id along with the agent’s first response.
    """
    data = request.json
    game_id = data.get("game_id", "")
    user_uuid = data.get("user_uuid", "NA")

    utils.token_gen.update_config()
    game = utils.get_game(game_id)
    if game == {}:
        return jsonify({"error": "Game not found."}), 404
    prompt = game.get("prompt")
    utils.token_gen.update_config()
    gamedev = utils.get_gamedev_by_id(game["game_developer"])
    if gamedev == {}:
        return jsonify({"error": "GameDev not found."}), 404
    prompt_suffix = f"""\nThe Winning Condition:\n{game.get("winning_condition")}  \n\n The amount is {game.get("cost_in_eth")} and the recipient_wallet is  {gamedev.get("Wallet Address")}. You need to deduct this on the start of the game everytime. This is absolutely important.
    The Reward for sucess is {game.get("reward_in_tokens")}. You need to add this to the user's wallet in case the user won. You need to use the transfer_token tool for this. 
    The Game Developer uuid is {game["game_developer"]}.
    The user UUID is {user_uuid}. This is important for the payment of the game fee. The Game UUID is {game_id}.
    The Token address for the reward token is {gamedev["Token"]}."""
    # Initialize a new agent instance.
    agent_executor, config = initialize_agent()

    # Prime the conversation with the initial prompt.
    initial_response = ""
    for chunk in agent_executor.stream(
        {"messages": [HumanMessage(content=prompt + prompt_suffix)]}, config
    ):
        if "agent" in chunk:
            # Capture the agent's response (the last such chunk will be used).
            initial_response = chunk["agent"]["messages"][0].content

    # Generate a unique session ID and store the agent instance and config.
    session_id = str(uuid.uuid4())
    game_test_sessions[session_id] = (agent_executor, config)

    return (
        jsonify(
            {
                "session_id": session_id,
                "message": "Game test session started.",
                "initial_response": initial_response,
            }
        ),
        201,
    )


@app.route("/chat/<session_id>", methods=["POST"])
def chat(session_id):
    """
    Accepts a user message for the given session and returns the agent's response.
    Expects JSON input with a "message" key.
    """
    data = request.json
    user_input = data.get("message", "")

    if session_id not in game_test_sessions:
        return jsonify({"error": "Session not found."}), 404

    agent_executor, config = game_test_sessions[session_id]

    # Send the user's message to the agent and collect the response.
    response_text = ""
    for chunk in agent_executor.stream(
        {"messages": [HumanMessage(content=user_input)]}, config
    ):
        if "agent" in chunk:
            print(chunk["agent"]["messages"][0].content)
            response_text = chunk["agent"]["messages"][0].content
        elif "tools" in chunk:
            print(chunk["tools"]["messages"][0].content)
    return jsonify({"response": response_text})


@app.route("/end_game_test/<session_id>", methods=["POST"])
def end_game_test(session_id):
    """
    Ends the game test session identified by the session_id.
    """
    if session_id in game_test_sessions:
        del game_test_sessions[session_id]
        return jsonify({"message": "Game test session ended."})
    else:
        return jsonify({"error": "Session not found."}), 404


def get_address_from_basename(basename):
    response = requests.get(f"{BLOCKSCOUT_API_URL}{basename}")
    print(response)
    if response.status_code == 200:
        data = response.json()
        if len(data) > 0:
            return data[0]["address"]
    return "Not available"


@app.route("/profile/<user_id>/info", methods=["GET"])
def get_profile_info(user_id):
    # In a real app you would extract the user identifier from the session or request token
    # and then fetch the corresponding profile from your database.
    utils.token_gen.update_config()
    user = utils.get_user_by_id(user_id)
    if user == {}:
        return jsonify({"error": "User not found."}), 404
    print(json.loads(eth_balance_tool(user["Wallet Address"])).get("eth_balance", 0))
    user_profile = {
        "email": user["Email"],
        "basename": user["Basename"],
        "wallet": get_address_from_basename(user["Basename"]),
        "custodial": user["Wallet Address"],
        "balance": json.loads(eth_balance_tool(user["Wallet Address"])).get(
            "eth_balance", 0
        ),
    }
    return jsonify(user_profile), 200


@app.route("/profile/<user_id>/tokens", methods=["GET"])
def get_profile_tokens(user_id):
    # In a real app you would extract the user identifier from the session or request token
    # and then fetch the corresponding profile from your database.
    utils.token_gen.update_config()
    user = utils.get_user_by_id(user_id)
    if user == {}:
        return jsonify({"error": "User not found."}), 404
    utils.token_gen.update_config()
    tokens = utils.fetch_tokens()
    if tokens == []:
        return jsonify({"error": "Tokens not found."}), 404
    wallet_address = user["Wallet Address"]
    tk_data = []
    for token in tokens:
        token_address = token["contract_address"]
        ERC20_ABI = contract_interface["abi"]
        contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)

        balance = contract.functions.balanceOf(wallet_address).call()
        decimals = contract.functions.decimals().call()
        tk_data.append(
            {
                "Token": token["name"],
                "Address": token["contract_address"],
                "Symbol": token["symbol"],
                "Balance": balance / (10**decimals),
            }
        )
    return jsonify(tk_data), 200


@app.route("/profile/<user_id>/qr", methods=["GET"])
def wallet_qr(user_id):
    utils.token_gen.update_config()
    user = utils.get_user_by_id(user_id)
    if user == {}:
        return jsonify({"error": "User not found."}), 404
    img = qrcode.make(user["Wallet Address"])
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=QRcode.png"
    response.mimetype = "image/png"
    return response


@app.route("/get_basenames", methods=["POST"])
def get_basenames():
    data = request.json
    if not data or "wallet_addresses" not in data:
        return jsonify({"error": "Missing wallet_addresses parameter"}), 400

    wallet_addresses = data["wallet_addresses"]
    unique_basenames = get_unique_basenames(wallet_addresses)
    return jsonify({"unique_basenames": unique_basenames})


@app.route("/withdraw_tokens", methods=["POST"])
def withdraw_tokens():
    data = request.json
    print(data)
    uuid = data["uuid"]
    token_address = data["token_address"]
    amount = float(data["amount"])
    utils.token_gen.update_config()
    user = utils.get_user_by_id(uuid)
    wallet_address = get_address_from_basename(user["Basename"])

    transaction_hashes = []

    myacc, message = get_wallet_from_uuid(uuid)
    if myacc:
        # ERC20 ABI for transfer
        ERC20_ABI = [
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
            {
                "constant": True,
                "inputs": [],
                "name": "decimals",
                "outputs": [{"name": "", "type": "uint8"}],
                "type": "function",
            },
        ]

        contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)

        # Convert to smallest unit
        decimals = contract.functions.decimals().call()
        value = int(amount * (10**decimals))

        # Build transaction
        transaction = contract.functions.transfer(
            wallet_address, value
        ).build_transaction(
            {
                "from": myacc.address,
                "gas": 100000,
                "gasPrice": web3.to_wei("1", "gwei"),
                "nonce": web3.eth.get_transaction_count(myacc.address),
            }
        )

        # Sign and send transaction
        signed_txn = web3.eth.account.sign_transaction(transaction, myacc.key.hex())
        tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)
        return (
            jsonify(
                {
                    "message": "Tokens withdrawn",
                    "transaction_hash": str(web3.to_hex(tx_hash)),
                }
            ),
            200,
        )
    else:
        return jsonify({"error": message}), 400


@app.route("/withdraw_eth", methods=["POST"])
def withdraw_eth():
    data = request.json
    uuid = data["uuid"]
    amount = float(data["amount"])
    print(data)
    utils.token_gen.update_config()
    user = utils.get_user_by_id(uuid)
    wallet_address = get_address_from_basename(user["Basename"])

    myacc, message = get_wallet_from_uuid(uuid)
    if not myacc:
        return jsonify({"error": message}), 400

    # Convert amount to Wei
    value = web3.to_wei(amount, "ether")
    gas_price = web3.eth.gas_price
    print(f"Gas Price: {gas_price}")
    print(f"Value: {value}")
    # Build transaction
    transaction = {
        "to": wallet_address,
        "value": value,
        "gas": 21000,
        "gasPrice": web3.eth.gas_price,
        "nonce": web3.eth.get_transaction_count(myacc.address),
        "chainId": web3.eth.chain_id,
    }

    # Sign and send transaction
    signed_txn = web3.eth.account.sign_transaction(transaction, myacc.key.hex())
    tx_hash = web3.eth.send_raw_transaction(signed_txn.raw_transaction)

    return (
        jsonify({"message": "ETH withdrawn", "transaction_hash": web3.to_hex(tx_hash)}),
        200,
    )


if __name__ == "__main__":
    app.run(debug=True)
