import requests
from typing import Dict, List, Optional
import jwt
import time
from ecdsa import SigningKey, SECP256k1
import nilql
from typing import List
import json
import uuid
import dotenv, os, datetime
from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.prebuilt import create_react_agent

# Import CDP Agentkit Langchain Extension.
from cdp_langchain.agent_toolkits import CdpToolkit
from cdp_langchain.utils import CdpAgentkitWrapper

dotenv.load_dotenv()
import traceback

NODE_CONFIG = {
    "node_a": {
        "url": os.environ.get("NODE_A_URL", ""),
        "did": os.environ.get("NODE_A_DID", ""),
    },
    "node_b": {
        "url": os.environ.get("NODE_B_URL", ""),
        "did": os.environ.get("NODE_B_DID", ""),
    },
    "node_c": {
        "url": os.environ.get("NODE_C_URL", ""),
        "did": os.environ.get("NODE_C_DID", ""),
    },
}

# Org DID
ORG_DID = os.environ.get("ORG_DID", "")

# Org secret key
ORG_SECRET_KEY = os.environ.get("ORG_SECRET_KEY", "")

# Number of nodes for secret sharing
NUM_NODES = len(NODE_CONFIG)


class NilDBAPI:
    def __init__(self, node_config: Dict):
        self.nodes = node_config

    def data_upload(self, node_name: str, schema_id: str, payload: list) -> bool:
        """Create/upload records in the specified node and schema."""
        try:
            node = self.nodes[node_name]
            headers = {
                "Authorization": f'Bearer {node["jwt"]}',
                "Content-Type": "application/json",
            }

            body = {"schema": schema_id, "data": payload}
            print(f" Headers {headers}\n", f"Body {body}")
            response = requests.post(
                f"{node['url']}/api/v1/data/create", headers=headers, json=body
            )
            print(response.json())
            return (
                response.status_code == 200
                and response.json().get("data", {}).get("errors", []) == []
            )
        except Exception as e:
            print(
                f"Error creating records in {node_name}: {str(traceback.format_exc())}"
            )
            return False

    def data_update(
        self, node_name: str, schema_id: str, filter_dict: dict, update_dict: dict
    ) -> bool:
        """Update records in the specified node and schema."""
        try:
            node = self.nodes[node_name]
            headers = {
                "Authorization": f'Bearer {node["jwt"]}',
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            body = {
                "schema": schema_id,
                "filter": filter_dict,
                "update": {"$set": update_dict},
            }
            print(body)
            response = requests.post(
                f"{node['url']}/api/v1/data/update", headers=headers, json=body
            )

            if response.status_code == 200:
                return response.json().get("data", {}).get("errors", []) == []
            else:
                print(
                    f"Failed to update data in {node_name}: {response.status_code} {response.text}"
                )
                return False

        except Exception as e:
            print(f"Error updating data in {node_name}: {str(traceback.format_exc())}")
            return False

    def data_delete(self, node_name: str, schema_id: str, filter_dict: dict) -> bool:
        """Update records in the specified node and schema."""
        try:
            node = self.nodes[node_name]
            headers = {
                "Authorization": f'Bearer {node["jwt"]}',
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            body = {"schema": schema_id, "filter": filter_dict}

            response = requests.post(
                f"{node['url']}/api/v1/data/delete", headers=headers, json=body
            )

            if response.status_code == 200:
                return response.json().get("data", {}).get("errors", []) == []
            else:
                print(
                    f"Failed to Delete data in {node_name}: {response.status_code} {response.text}"
                )
                return False

        except Exception as e:
            print(f"Error Delete data in {node_name}: {str(traceback.format_exc())}")
            return False

    def data_read(
        self, node_name: str, schema_id: str, filter_dict: Optional[dict] = None
    ) -> List[Dict]:
        """Read data from the specified node and schema."""
        try:
            node = self.nodes[node_name]
            headers = {
                "Authorization": f'Bearer {node["jwt"]}',
                "Content-Type": "application/json",
            }

            body = {
                "schema": schema_id,
                "filter": filter_dict if filter_dict is not None else {},
            }

            response = requests.post(
                f"{node['url']}/api/v1/data/read", headers=headers, json=body
            )

            if response.status_code == 200:
                return response.json().get("data", [])
            return []
        except Exception as e:
            print(f"Error reading data from {node_name}: {str(traceback.format_exc())}")
            return []

    def query_execute(
        self, node_name: str, query_id: str, variables: Optional[dict] = None
    ) -> List[Dict]:
        """Execute a query on the specified node with advanced filtering."""
        try:
            node = self.nodes[node_name]
            headers = {
                "Authorization": f'Bearer {node["jwt"]}',
                "Content-Type": "application/json",
            }

            payload = {
                "id": query_id,
                "variables": variables if variables is not None else {},
            }

            response = requests.post(
                f"{node['url']}/api/v1/queries/execute", headers=headers, json=payload
            )

            if response.status_code == 200:
                return response.json().get("data", [])
            return []
        except Exception as e:
            print(
                f"Error executing query on {node_name}: {str(traceback.format_exc())}"
            )
            return []

    def create_schema(self, node_name: str, payload: dict = None) -> List[Dict]:
        """Create a schema in the specified node."""
        try:
            node = self.nodes[node_name]
            headers = {
                "Authorization": f'Bearer {node["jwt"]}',
                "Content-Type": "application/json",
            }
            response = requests.post(
                f"{node['url']}/api/v1/schemas",
                headers=headers,
                json=payload if payload is not None else {},
            )

            if response.status_code == 200 and response.json().get("errors", []) == []:
                print(f"Schema created successfully on {node_name}.")
                return response.json().get("data", [])
            else:
                print(
                    f"Failed to create schema on {node_name}: {response.status_code} {response.text}"
                )
                return []

        except Exception as e:
            print(
                f"Error creating schema on {node_name}: {str(traceback.format_exc())}"
            )
            return []

    def create_query(self, node_name: str, payload: dict = {}) -> List[Dict]:
        """Create a query in the specified node."""
        try:
            node = self.nodes[node_name]
            headers = {
                "Authorization": f'Bearer {node["jwt"]}',
                "Content-Type": "application/json",
            }

            response = requests.post(
                f"{node['url']}/api/v1/queries",
                headers=headers,
                json=payload if payload is not None else {},
            )

            if response.status_code == 200:
                return response.json().get("data", [])
            else:
                print(
                    f"Failed to create query in {node_name}: {response.status_code} {response.text}"
                )
                return []

        except Exception as e:
            print(f"Error creating query in {node_name}: {str(traceback.format_exc())}")
            return []


class TokenGenerator:

    def create_jwt(
        self,
        secret_key: str = None,
        org_did: str = None,
        node_ids: list = None,
        ttl: int = 3600,
    ) -> list:
        """
        Create JWTs signed with ES256K for multiple node_ids
        """

        # Convert the secret key from hex to bytes
        private_key = bytes.fromhex(secret_key)
        signer = SigningKey.from_string(private_key, curve=SECP256k1)

        tokens = []
        for node_id in node_ids:
            # Create payload for each node_id
            payload = {"iss": org_did, "aud": node_id, "exp": int(time.time()) + ttl}

            # Create and sign the JWT
            token = jwt.encode(payload, signer.to_pem(), algorithm="ES256K")
            tokens.append(token)

        return tokens

    def update_config(self) -> None:
        """
        Update the cluster config with short-lived JWTs
        """
        # Create tokens for the nodes with 60s TTL
        tokens = self.create_jwt(
            ORG_SECRET_KEY, ORG_DID, [node["did"] for node in NODE_CONFIG.values()], 60
        )
        for node, token in zip(NODE_CONFIG.values(), tokens):
            node["jwt"] = token


class DataEncryption:
    def __init__(self, num_nodes: int):
        self.num_nodes = num_nodes
        self.secret_key = nilql.ClusterKey.generate(
            {"nodes": [{}] * num_nodes}, {"store": True}
        )

    def encrypt_password(self, password: str) -> List[str]:
        """Encrypt password using secret sharing."""
        try:
            encrypted_shares = nilql.encrypt(self.secret_key, password)

            return list(encrypted_shares)
        except Exception as e:
            raise Exception(f"Encryption failed: {str(traceback.format_exc())}")

    def decrypt_password(self, encoded_shares: List[str]) -> str:
        """Decrypt password from shares."""
        try:
            decoded_shares = []
            for share in encoded_shares:
                decoded_shares.append(share)

            return str(nilql.decrypt(self.secret_key, decoded_shares))
        except Exception as e:
            raise Exception(f"Decryption failed: {str(traceback.format_exc())}")


class SchemaManager:
    def __init__(self):
        self.schema_ids = dict()

    def define_collection(self, name: str, schema: dict) -> bool:
        """Define a collection and register it on the nodes."""
        try:
            # Generate and id for the schema
            schema_id = str(uuid.uuid4())

            # Create schema across nodes
            success = True
            for i, node_name in enumerate(NODE_CONFIG.keys()):
                payload = {
                    "_id": schema_id,
                    "name": name,
                    "keys": ["_id"],
                    "schema": schema,
                }
                if not nildb_api.create_schema(node_name, payload):
                    success = False
                    break

            # Store the schema_id
            self.schema_ids[name] = schema_id
            schema_ids = json.load(open("schema_structure.json", "r"))
            schema_ids["Schema_ids"][name] = schema_id
            json.dump(schema_ids, open("schema_structure.json", "w"))
            return success
        except Exception as e:
            print(f"Error creating schema: {str(traceback.format_exc())}")
            return False


nildb_api = NilDBAPI(NODE_CONFIG)
token_gen = TokenGenerator()
schema_manager = SchemaManager()
encryption = DataEncryption(NUM_NODES)


def init_schema():
    schema_ids = json.load(open("schema_structure.json", "r"))
    token_gen.update_config()
    if schema_ids["Schema_ids"] == dict():
        schema_data = json.load(open("schema.json", "r"))
        schema_manager.define_collection("Token", schema_data["Token"])
        schema_manager.define_collection("GameDeveloper", schema_data["GameDeveloper"])
        schema_manager.define_collection("Game", schema_data["Game"])
        schema_manager.define_collection("User", schema_data["User"])
    else:
        schema_manager.schema_ids = schema_ids["Schema_ids"]
        print("Schema already initialized")


init_schema()


def upload_user(
    email: str, basename: str, password: str, wallet_address: str, private_key: str
) -> bool:
    """Create and store encrypted user data across nodes."""
    try:
        # Generate unique User ID
        user_id = str(uuid.uuid4())

        # Encrypt sensitive data (password & private_key)
        encrypted_password_shares = encryption.encrypt_password(password)
        encrypted_private_key_shares = encryption.encrypt_password(
            private_key
        )  # Assuming same encryption method

        # Store shares across nodes
        success = True
        for i, node_name in enumerate(["node_a", "node_b", "node_c"]):
            user_data = {
                "_id": user_id,
                "email": email,
                "basename": basename,
                "password": encrypted_password_shares[i],
                "wallet_address": wallet_address,
                "private_key": encrypted_private_key_shares[i],
            }

            print(schema_manager.schema_ids)
            if not nildb_api.data_upload(
                node_name, schema_manager.schema_ids["User"], [user_data]
            ):
                success = False
                break

        return success
    except Exception as e:
        print(f"Error creating user: {str(traceback.format_exc())}")
        return False


def fetch_users() -> List[Dict]:
    """Fetch and decrypt user data from nodes."""
    try:
        # Fetch from all nodes
        users = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_users = nildb_api.data_read(
                node_name, schema_manager.schema_ids["User"]
            )
            print("node_users", node_users)
            for user in node_users:
                user_id = user["_id"]
                if user_id not in users:
                    users[user_id] = {
                        "email": user["email"],
                        "basename": user["basename"],
                        "wallet_address": user["wallet_address"],
                        "password_shares": [],
                        "private_key_shares": [],
                    }
                users[user_id]["password_shares"].append(user["password"])
                users[user_id]["private_key_shares"].append(user["private_key"])

        # Decrypt password & private key
        decrypted_users = []
        for user_id, user_data in users.items():
            if (
                len(user_data["password_shares"]) == NUM_NODES
                and len(user_data["private_key_shares"]) == NUM_NODES
            ):
                try:
                    decrypted_password = encryption.decrypt_password(
                        user_data["password_shares"]
                    )
                    decrypted_private_key = encryption.decrypt_password(
                        user_data["private_key_shares"]
                    )
                    decrypted_users.append(
                        {
                            "Email": user_data["email"],
                            "Basename": user_data["basename"],
                            "Wallet Address": user_data["wallet_address"],
                            "Password": decrypted_password,
                            "Private Key": decrypted_private_key,
                        }
                    )
                except Exception as e:
                    print(
                        f"Could not decrypt user {user_id}: {str(traceback.format_exc())}"
                    )

        return decrypted_users
    except Exception as e:
        print(f"Error fetching users: {str(traceback.format_exc())}")
        return []


def login_user(email: str, password: str) -> Dict:
    """Authenticate user based on email filter and decrypt stored credentials."""
    try:
        # Define the filter criteria
        filter_dict = {"email": email}

        # Fetch from all nodes using the filter
        users = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_users = nildb_api.data_read(
                node_name, schema_manager.schema_ids["User"], filter_dict
            )
            print("Filtered Users:", node_users)

            for user in node_users:
                user_id = user["_id"]
                if user_id not in users:
                    users[user_id] = {
                        "user_id": user_id,
                        "email": user["email"],
                        "basename": user["basename"],
                        "wallet_address": user["wallet_address"],
                        "password_shares": [],
                        "private_key_shares": [],
                    }
                users[user_id]["password_shares"].append(user["password"])
                users[user_id]["private_key_shares"].append(user["private_key"])

        # Validate user data
        if not users:
            print("User not found.")
            return {}

        # Since email is unique, there should be only one match
        user_id, user_data = next(iter(users.items()))

        # Ensure all password shares are retrieved before decryption
        if len(user_data["password_shares"]) == NUM_NODES:
            decrypted_password = encryption.decrypt_password(
                user_data["password_shares"]
            )
        else:
            print("Incomplete data, unable to decrypt password.")
            return {}

        # Ensure all private key shares are retrieved before decryption
        if len(user_data["private_key_shares"]) == NUM_NODES:
            decrypted_private_key = encryption.decrypt_password(
                user_data["private_key_shares"]
            )
        else:
            print("Incomplete data, unable to decrypt private key.")
            return {}
        if decrypted_password != password:
            return {}
        # Return user details upon successful retrieval
        else:
            return {
                "uuid": user_data["user_id"],
                "Email": user_data["email"],
                "Basename": user_data["basename"],
                "Wallet Address": user_data["wallet_address"],
                "Password": decrypted_password,
                "Private Key": decrypted_private_key,
            }

    except Exception as e:
        print(f"Error during login: {str(traceback.format_exc())}")
        return {}


def get_user_by_id(_id: str) -> Dict:
    """Authenticate user based on email filter and decrypt stored credentials."""
    try:
        # Define the filter criteria
        filter_dict = {"_id": _id}

        # Fetch from all nodes using the filter
        users = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_users = nildb_api.data_read(
                node_name, schema_manager.schema_ids["User"], filter_dict
            )
            print("Filtered Users:", node_users)

            for user in node_users:
                user_id = user["_id"]
                if user_id not in users:
                    users[user_id] = {
                        "email": user["email"],
                        "basename": user["basename"],
                        "wallet_address": user["wallet_address"],
                        "password_shares": [],
                        "private_key_shares": [],
                    }
                users[user_id]["password_shares"].append(user["password"])
                users[user_id]["private_key_shares"].append(user["private_key"])

        # Validate user data
        if not users:
            print("User not found.")
            return {}

        # Since email is unique, there should be only one match
        user_id, user_data = next(iter(users.items()))

        # Ensure all password shares are retrieved before decryption
        if len(user_data["password_shares"]) == NUM_NODES:
            decrypted_password = encryption.decrypt_password(
                user_data["password_shares"]
            )
        else:
            print("Incomplete data, unable to decrypt password.")
            return {}

        # Ensure all private key shares are retrieved before decryption
        if len(user_data["private_key_shares"]) == NUM_NODES:
            decrypted_private_key = encryption.decrypt_password(
                user_data["private_key_shares"]
            )
        else:
            print("Incomplete data, unable to decrypt private key.")
            return {}
        return {
            "Email": user_data["email"],
            "Basename": user_data["basename"],
            "Wallet Address": user_data["wallet_address"],
            "Password": decrypted_password,
            "Private Key": decrypted_private_key,
        }

    except Exception as e:
        print(f"Error during login: {str(traceback.format_exc())}")
        return {}


def upload_token(
    name: str,
    symbol: str,
    decimals: int,
    total_supply: str,
    contract_address: str,
    creator: str,
) -> bool:
    """Create and store token data across nodes."""
    try:
        # Generate unique Token ID
        token_id = str(uuid.uuid4())

        # Store token data across nodes
        success = True
        for node_name in ["node_a", "node_b", "node_c"]:
            token_data = {
                "_id": token_id,
                "name": name,
                "symbol": symbol,
                "decimals": decimals,
                "total_supply": total_supply,
                "balance": total_supply,
                "contract_address": contract_address,
                "creator": creator,
            }
            if not nildb_api.data_upload(
                node_name, schema_manager.schema_ids["Token"], [token_data]
            ):
                success = False
                break

        return success
    except Exception as e:
        print(f"Error creating token: {str(e)}")
        return False


def fetch_tokens() -> List[Dict]:
    """Fetch all token data from nodes."""
    try:
        tokens = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_tokens = nildb_api.data_read(
                node_name, schema_manager.schema_ids["Token"]
            )
            print("Fetched Tokens:", node_tokens)

            for token in node_tokens:
                token_id = token["_id"]
                if token_id not in tokens:
                    tokens[token_id] = {
                        "name": token["name"],
                        "symbol": token["symbol"],
                        "decimals": token["decimals"],
                        "total_supply": token["total_supply"],
                        "balance": token["balance"],
                        "contract_address": token["contract_address"],
                        "creator": token["creator"],
                    }

        return list(tokens.values())

    except Exception as e:
        print(f"Error fetching tokens: {str(e)}")
        return []


def get_token(symbol: str) -> Dict:
    """Fetch a specific token based on its symbol."""
    try:
        filter_dict = {"symbol": symbol}

        tokens = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_tokens = nildb_api.data_read(
                node_name, schema_manager.schema_ids["Token"], filter_dict
            )
            print("Filtered Tokens:", node_tokens)

            for token in node_tokens:
                token_id = token["_id"]
                if token_id not in tokens:
                    tokens[token_id] = {
                        "name": token["name"],
                        "symbol": token["symbol"],
                        "decimals": token["decimals"],
                        "total_supply": token["total_supply"],
                        "balance": token["balance"],
                        "contract_address": token["contract_address"],
                        "creator": token["creator"],
                    }

        if not tokens:
            print("Token not found.")
            return {}

        return list(tokens.values())[0]  # Return the first match

    except Exception as e:
        print(f"Error retrieving token: {str(e)}")
        return {}


def get_token_by_gamedev_wallet(wallet: str) -> Dict:
    """Fetch a specific token based on its symbol."""
    try:
        filter_dict = {"creator": wallet}

        tokens = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_tokens = nildb_api.data_read(
                node_name, schema_manager.schema_ids["Token"], filter_dict
            )
            print("Filtered Tokens:", node_tokens)

            for token in node_tokens:
                token_id = token["_id"]
                if token_id not in tokens:
                    tokens[token_id] = {
                        "name": token["name"],
                        "symbol": token["symbol"],
                        "decimals": token["decimals"],
                        "total_supply": token["total_supply"],
                        "balance": token["balance"],
                        "contract_address": token["contract_address"],
                        "creator": token["creator"],
                    }

        if not tokens:
            print("Token not found.")
            return {}

        return list(tokens.values())[0]  # Return the first match

    except Exception as e:
        print(f"Error retrieving token: {str(e)}")
        return {}


def upload_gamedev(
    gamedev_id: str,
    email: str,
    company_name: str,
    password: str,
    website: str,
    description: str,
    wallet_address: str,
    private_key: str,
    verified: bool,
    total_revenue: int,
    active_status: bool,
) -> bool:
    """Create and store GameDev data across nodes."""
    try:
        # Encrypt sensitive data (password & private_key)
        encrypted_password_shares = encryption.encrypt_password(password)
        encrypted_private_key_shares = encryption.encrypt_password(private_key)

        # Store GameDev data across nodes
        success = True
        for i, node_name in enumerate(["node_a", "node_b", "node_c"]):
            gamedev_data = {
                "_id": gamedev_id,
                "email": email,
                "company_name": company_name,
                "password": encrypted_password_shares[i],
                "website": website,
                "description": description,
                "wallet_address": wallet_address,
                "private_key": encrypted_private_key_shares[i],
                "verified": verified,
                "total_revenue": total_revenue,
                "active_status": active_status,
                "token": "",
            }
            if not nildb_api.data_upload(
                node_name, schema_manager.schema_ids["GameDeveloper"], [gamedev_data]
            ):
                success = False
                break

        return success
    except Exception as e:
        print(f"Error creating GameDev account: {str(e)}")
        return False


def fetch_gamedevs() -> List[Dict]:
    """Fetch all GameDev data from nodes."""
    try:
        gamedevs = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_gamedevs = nildb_api.data_read(
                node_name, schema_manager.schema_ids["GameDeveloper"]
            )
            print("Fetched GameDevs:", node_gamedevs)

            for gamedev in node_gamedevs:
                gamedev_id = gamedev["_id"]
                if gamedev_id not in gamedevs:
                    gamedevs[gamedev_id] = {
                        "email": gamedev["email"],
                        "company_name": gamedev["company_name"],
                        "website": gamedev["website"],
                        "description": gamedev["description"],
                        "wallet_address": gamedev["wallet_address"],
                        "verified": gamedev["verified"],
                        "total_revenue": gamedev["total_revenue"],
                        "active_status": gamedev["active_status"],
                        "token": gamedev["token"],
                    }

        return list(gamedevs.values())

    except Exception as e:
        print(f"Error fetching GameDev accounts: {str(e)}")
        return []


def login_gamedev(email: str, password: str) -> Dict:
    """Authenticate GameDev based on email filter and decrypt stored credentials."""
    try:
        filter_dict = {"email": email}

        gamedevs = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_gamedevs = nildb_api.data_read(
                node_name, schema_manager.schema_ids["GameDeveloper"], filter_dict
            )
            print("Filtered GameDevs:", node_gamedevs)

            for gamedev in node_gamedevs:
                gamedev_id = gamedev["_id"]
                if gamedev_id not in gamedevs:
                    gamedevs[gamedev_id] = {
                        "_id": gamedev_id,
                        "email": gamedev["email"],
                        "company_name": gamedev["company_name"],
                        "website": gamedev["website"],
                        "description": gamedev["description"],
                        "wallet_address": gamedev["wallet_address"],
                        "verified": gamedev["verified"],
                        "total_revenue": gamedev["total_revenue"],
                        "active_status": gamedev["active_status"],
                        "token": gamedev["token"],
                        "password_shares": [],
                        "private_key_shares": [],
                    }
                gamedevs[gamedev_id]["password_shares"].append(gamedev["password"])
                gamedevs[gamedev_id]["private_key_shares"].append(
                    gamedev["private_key"]
                )

        if not gamedevs:
            print("GameDev not found.")
            return {}

        # Since email is unique, there should be only one match
        gamedev_id, gamedev_data = next(iter(gamedevs.items()))

        # Ensure all password shares are retrieved before decryption
        if len(gamedev_data["password_shares"]) == NUM_NODES:
            decrypted_password = encryption.decrypt_password(
                gamedev_data["password_shares"]
            )
        else:
            print("Incomplete data, unable to decrypt password.")
            return {}

        # Ensure all private key shares are retrieved before decryption
        if len(gamedev_data["private_key_shares"]) == NUM_NODES:
            decrypted_private_key = encryption.decrypt_password(
                gamedev_data["private_key_shares"]
            )
        else:
            print("Incomplete data, unable to decrypt private key.")
            return {}
        if decrypted_password != password:
            return {}
        else:
            return {
                "_id": gamedev_data["_id"],
                "Email": gamedev_data["email"],
                "Company Name": gamedev_data["company_name"],
                "Website": gamedev_data["website"],
                "Description": gamedev_data["description"],
                "Wallet Address": gamedev_data["wallet_address"],
                "Verified": gamedev_data["verified"],
                "Total Revenue": gamedev_data["total_revenue"],
                "Active Status": gamedev_data["active_status"],
                "Token": gamedev_data["token"],
                "Password": decrypted_password,
                "Private Key": decrypted_private_key,
            }

    except Exception as e:
        print(f"Error during GameDev login: {str(e)}")
        return {}


def get_gamedev_by_id(uid: str) -> Dict:
    """Authenticate GameDev based on email filter and decrypt stored credentials."""
    try:
        filter_dict = {"_id": uid}

        gamedevs = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_gamedevs = nildb_api.data_read(
                node_name, schema_manager.schema_ids["GameDeveloper"], filter_dict
            )
            print("Filtered GameDevs:", node_gamedevs)

            for gamedev in node_gamedevs:
                gamedev_id = gamedev["_id"]
                if gamedev_id not in gamedevs:
                    gamedevs[gamedev_id] = {
                        "_id": gamedev_id,
                        "email": gamedev["email"],
                        "company_name": gamedev["company_name"],
                        "website": gamedev["website"],
                        "description": gamedev["description"],
                        "wallet_address": gamedev["wallet_address"],
                        "verified": gamedev["verified"],
                        "total_revenue": gamedev["total_revenue"],
                        "active_status": gamedev["active_status"],
                        "token": gamedev["token"],
                        "password_shares": [],
                        "private_key_shares": [],
                    }
                gamedevs[gamedev_id]["password_shares"].append(gamedev["password"])
                gamedevs[gamedev_id]["private_key_shares"].append(
                    gamedev["private_key"]
                )

        if not gamedevs:
            print("GameDev not found.")
            return {}

        # Since email is unique, there should be only one match
        gamedev_id, gamedev_data = next(iter(gamedevs.items()))

        # Ensure all password shares are retrieved before decryption
        if len(gamedev_data["password_shares"]) == NUM_NODES:
            decrypted_password = encryption.decrypt_password(
                gamedev_data["password_shares"]
            )
        else:
            print("Incomplete data, unable to decrypt password.")
            return {}

        # Ensure all private key shares are retrieved before decryption
        if len(gamedev_data["private_key_shares"]) == NUM_NODES:
            decrypted_private_key = encryption.decrypt_password(
                gamedev_data["private_key_shares"]
            )
        else:
            print("Incomplete data, unable to decrypt private key.")
            return {}
        return {
            "_id": gamedev_data["_id"],
            "Email": gamedev_data["email"],
            "Company Name": gamedev_data["company_name"],
            "Website": gamedev_data["website"],
            "Description": gamedev_data["description"],
            "Wallet Address": gamedev_data["wallet_address"],
            "Verified": gamedev_data["verified"],
            "Total Revenue": gamedev_data["total_revenue"],
            "Active Status": gamedev_data["active_status"],
            "Token": gamedev_data["token"],
            "Password": decrypted_password,
            "Private Key": decrypted_private_key,
        }

    except Exception as e:
        print(f"Error during GameDev login: {str(e)}")
        return {}


def update_gamedev(
    gamedev_id: str,
    email: str,
    company_name: str,
    password: str,
    website: str,
    description: str,
    wallet_address: str,
    private_key: str,
    verified: bool,
    total_revenue: int,
    active_status: bool,
    token: str,
) -> bool:
    """Create and store GameDev data across nodes."""
    try:
        filter_dict = {"_id": gamedev_id}
        # Store GameDev data across nodes
        success = True
        for i, node_name in enumerate(["node_a", "node_b", "node_c"]):
            gamedev_data = {
                "email": email,
                "company_name": company_name,
                "website": website,
                "description": description,
                "wallet_address": wallet_address,
                "verified": verified,
                "total_revenue": total_revenue,
                "active_status": active_status,
                "token": token,
            }
            if not nildb_api.data_update(
                node_name,
                schema_manager.schema_ids["GameDeveloper"],
                filter_dict,
                gamedev_data,
            ):
                success = False
                break

        return success
    except Exception as e:
        print(f"Error creating GameDev account: {str(e)}")
        return False


def upload_game(
    title: str,
    description: str,
    prompt: str,
    winning_condition: str,
    cost_in_eth: float,
    reward_in_tokens: float,
    card_type: int,
    developer_id: str,
    imagePath: str,
) -> bool:
    """Create and store Game data across nodes."""
    try:
        # Generate unique Game ID
        game_id = str(uuid.uuid4())

        # Store game data across nodes
        success = True
        for node_name in ["node_a", "node_b", "node_c"]:
            game_data = {
                "_id": game_id,
                "title": title,
                "description": description,
                "prompt": prompt,
                "winning_condition": winning_condition,
                "cost_in_eth": cost_in_eth,
                "reward_in_tokens": reward_in_tokens,
                "game_type": card_type,
                "imagePath": imagePath,
                "revenue": 0,
                "players": 0,
                "status": "Created",
                "game_developer": developer_id,
            }
            if not nildb_api.data_upload(
                node_name, schema_manager.schema_ids["Game"], [game_data]
            ):
                success = False
                break

        return success
    except Exception as e:
        print(f"Error creating game: {str(e)}")
        return False


def update_game(
    game_id: str,
    title: str,
    description: str,
    prompt: str,
    winning_condition: str,
    cost_in_eth: float,
    reward_in_tokens: float,
    card_type: int,
    revenue: str,
    players: str,
    imagePath: str,
    status: str,
) -> bool:
    """Updating Game data across nodes."""
    try:
        filter_dict = {"_id": game_id}
        # Store GameDev data across nodes
        success = True
        for i, node_name in enumerate(["node_a", "node_b", "node_c"]):
            gamedev_data = {
                "title": title,
                "description": description,
                "prompt": prompt,
                "winning_condition": winning_condition,
                "cost_in_eth": cost_in_eth,
                "reward_in_tokens": reward_in_tokens,
                "game_type": card_type,
                "imagePath": imagePath,
                "revenue": revenue,
                "players": players,
                "status": status,
            }
            if not nildb_api.data_update(
                node_name,
                schema_manager.schema_ids["Game"],
                filter_dict,
                gamedev_data,
            ):
                success = False
                break

        return success
    except Exception as e:
        print(f"Error Updating Game : {str(e)}")
        return False


def fetch_games() -> List[Dict]:
    """Fetch all Game data from nodes."""
    try:
        games = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_games = nildb_api.data_read(
                node_name, schema_manager.schema_ids["Game"]
            )
            print("Fetched Games:", node_games)

            for game in node_games:
                game_id = game["_id"]
                if game_id not in games:
                    games[game_id] = {
                        "title": game["title"],
                        "description": game["description"],
                        "prompt": game["prompt"],
                        "winning_condition": game["winning_condition"],
                        "cost_in_eth": game["cost_in_eth"],
                        "reward_in_tokens": game["reward_in_tokens"],
                        "game_type": game["game_type"],
                        "status": game["status"],
                        "revenue": game["revenue"],
                        "players": game["players"],
                        "imagePath": game["imagePath"],
                        "game_developer": game["game_developer"],
                    }

        return list(games.values())

    except Exception as e:
        print(f"Error fetching games: {str(e)}")
        return []


def get_game(uid: str) -> Dict:
    """Fetch a specific game based on its title."""
    try:
        filter_dict = {"_id": uid}

        games = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_games = nildb_api.data_read(
                node_name, schema_manager.schema_ids["Game"], filter_dict
            )
            print("Filtered Games:", node_games)

            for game in node_games:
                game_id = game["_id"]
                if game_id not in games:
                    games[game_id] = {
                        "title": game["title"],
                        "description": game["description"],
                        "prompt": game["prompt"],
                        "winning_condition": game["winning_condition"],
                        "cost_in_eth": game["cost_in_eth"],
                        "reward_in_tokens": game["reward_in_tokens"],
                        "game_type": game["game_type"],
                        "revenue": game["revenue"],
                        "status": game["status"],
                        "players": game["players"],
                        "imagePath": game["imagePath"],
                        "game_developer": game["game_developer"],
                    }

        if not games:
            print("Game not found.")
            return {}

        return list(games.values())[0]  # Return the first match

    except Exception as e:
        print(f"Error retrieving game: {str(e)}")
        return {}


def get_games_by_gamedev(gamedev_id: str) -> Dict:
    """Fetch a specific game based on its title."""
    try:
        filter_dict = {"game_developer": gamedev_id}

        games = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_games = nildb_api.data_read(
                node_name, schema_manager.schema_ids["Game"], filter_dict
            )
            print("Filtered Games:", node_games)

            for game in node_games:
                game_id = game["_id"]
                if game_id not in games:
                    games[game_id] = {
                        "uid": game_id,
                        "title": game["title"],
                        "description": game["description"],
                        "prompt": game["prompt"],
                        "winning_condition": game["winning_condition"],
                        "cost_in_eth": game["cost_in_eth"],
                        "reward_in_tokens": game["reward_in_tokens"],
                        "game_type": game["game_type"],
                        "status": game["status"],
                        "players": game["players"],
                        "revenue": game["revenue"],
                        "game_developer": game["game_developer"],
                        "imagePath": game["imagePath"],
                    }

        if not games:
            print("Game not found.")
            return {}

        return {"games": list(games.values())}

    except Exception as e:
        print(f"Error retrieving game: {str(e)}")
        return {}


def get_games_by_status(status: str) -> Dict:
    """Fetch a specific game based on its title."""
    try:
        filter_dict = {"status": status}

        games = {}
        for node_name in ["node_a", "node_b", "node_c"]:
            node_games = nildb_api.data_read(
                node_name, schema_manager.schema_ids["Game"], filter_dict
            )
            print("Filtered Games:", node_games)

            for game in node_games:
                game_id = game["_id"]
                if game_id not in games:
                    games[game_id] = {
                        "uid": game_id,
                        "title": game["title"],
                        "description": game["description"],
                        "prompt": game["prompt"],
                        "cost_in_eth": game["cost_in_eth"],
                        "reward_in_tokens": game["reward_in_tokens"],
                        "game_type": game["game_type"],
                        "status": game["status"],
                        "players": game["players"],
                        "revenue": game["revenue"],
                        "game_developer": game["game_developer"],
                        "imagePath": game["imagePath"],
                    }

        if not games:
            print("Game not found.")
            return {}

        return {"games": list(games.values())}

    except Exception as e:
        print(f"Error retrieving game: {str(e)}")
        return {}
