from flask import Flask, request, jsonify, render_template, redirect, url_for
import os
import uuid
import requests
from web3 import Web3
from solcx import compile_source, install_solc
import math
import datetime
import dotenv, os
import utils

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

# Import necessary classes from your LangChain/CDP Agentkit setup.
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

from cdp_langchain.agent_toolkits import CdpToolkit
from cdp_langchain.utils import CdpAgentkitWrapper

# Global dictionary to store conversation sessions.
game_test_sessions = {}


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

    # utils.token_gen.update_config()
    # utils.update_gamedev(
    #     myuuid,
    #     private_key=gamedev["Private Key"],
    #     company_name=gamedev["Company Name"],
    #     email=gamedev["Email"],
    #     website=gamedev["Website"],
    #     description=gamedev["Description"],
    #     wallet_address=gamedev["Wallet Address"],
    #     token=contract_address,
    #     password=gamedev["Password"],
    #     total_revenue=gamedev["Total Revenue"],
    #     active_status=gamedev["Active Status"],
    #     verified=False,
    # )
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
    return jsonify(games["games"]), 200


@app.route("/gamedev/create_game", methods=["POST"])
def create_game():
    data = request.form  # Use request.form for form data
    print(data)
    myuuid = data.get("uuid")
    utils.token_gen.update_config()
    utils.upload_game(
        title=data.get("game_title"),
        description=data.get("game_description"),
        prompt=data.get("prompt"),
        cost_in_eth=float(data.get("cost_in_eth")),
        reward_in_tokens=float(data.get("reward_in_tokens")),
        card_type=int(data.get("card_type", "prompt")),
        developer_id=myuuid,
    )

    return redirect(url_for("dash"))  # Redirect to the dashboard page


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
    for tool in tools:
        # For this example we only add the "deploy_token" tool.
        if tool.name == "deploy_token":
            all_tools.append(tool)

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
            "responses. Refrain from restating your tools' descriptions unless it is explicitly requested."
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

    utils.token_gen.update_config()
    game = utils.get_game(game_id)
    print(game)
    if game == {}:
        return jsonify({"error": "Game not found."}), 404
    prompt = game.get("prompt")
    # Initialize a new agent instance.
    agent_executor, config = initialize_agent()

    # Prime the conversation with the initial prompt.
    initial_response = ""
    for chunk in agent_executor.stream(
        {"messages": [HumanMessage(content=prompt)]}, config
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
            response_text = chunk["agent"]["messages"][0].content

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


if __name__ == "__main__":
    app.run(debug=True)
