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


if __name__ == "__main__":
    app.run(debug=True)
