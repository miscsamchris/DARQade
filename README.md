# DARQade - Web3 Gaming Platform

DARQade is a revolutionary gaming platform that combines AI, blockchain technology, and game development to create unique GameFi experiences. The platform enables game developers to create and monetize games while allowing players to earn rewards through gameplay.

## Features

### For Game Developers
- Create and deploy blockchain-integrated games
- Custom token creation for game economies
- Revenue tracking and analytics
- AI-powered game asset generation
- Flexible pricing plans
- Cross-platform deployment support

### For Players
- Play-to-earn mechanics
- Collection of game-specific meme coins
- AI-powered dynamic gameplay
- Community tournaments
- Cross-game token utility
- Wallet integration with Base network

## Technology Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML, TailwindCSS, JavaScript
- **Blockchain**: Web3.py, Base Network (Ethereum L2)
- **Database**: Distributed database system with node replication
- **AI Integration**: LangChain, CDP Agentkit
- **Asset Storage**: Cloudinary
- **Authentication**: Custom JWT-based system

## Prerequisites

- Python 3.8+
- Node.js and npm
- Web3 provider (e.g., MetaMask)
- Base Network connection
- Environment variables setup

## Installation

1. Clone the repository:
```bash
git clone https://github.com/miscsamchris/darqade.git
cd darqade
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
```

4. Configure your `.env` file with the following variables:
```bash
INFURA_KEY
PRIVATE_KEY
ORG_SECRET_KEY
ORG_DID
NODE_A_URL
NODE_A_DID
NODE_B_URL
NODE_B_DID
NODE_C_URL
NODE_C_DID
CDP_API_KEY_NAME
CDP_API_KEY_PRIVATE_KEY
OPENAI_API_KEY
CLOUDINARY_CLOUD_NAME
CLOUDINARY_API_KEY
CLOUDINARY_API_SECRET
```

5. Run the application:
```bash
python app.py
```

## Project Structure

```
Flask-Application/
├── app.py              # Main application file
├── utils.py            # Utility functions
├── static/            
│   └── images/        # Image assets
├── templates/
│   ├── index.html     # Game developer interface
│   └── user_index.html # Player interface
│   └── dashboard.html # Game developer interface
│   └── arcade.html # Player interface
└── requirements.txt    # Python dependencies
```

## Demo
[![Demo Video](https://img.youtube.com/vi/fJdL2zpo2kw/maxresdefault.jpg)](https://www.youtube.com/watch?v=fJdL2zpo2kw)

## Onchain Transactions

### Smart Contracts
 - https://sepolia.basescan.org/address/0x37f0f4a2e1c769d6a0b39d9e5ec554263a36b615#tokentxns
 - https://sepolia.basescan.org/address/0xa6dd15296f7dd0ffd3d2ab776e460f94787589f9#tokentxns

### AI Token Prize Distribution
 - https://sepolia.basescan.org/tx/0x420f1e6f5c883bf5837888b3a1d5753bc1323650af7ce0cb26217d013c51a960
 - https://sepolia.basescan.org/tx/0x51baae09e2395d20448ede2cb96dc0c753546b492521fbae3f6ad3c64827a082
 - https://sepolia.basescan.org/tx/0x3fa15d96b72563eea5cba47c9bf23560cacd5c993a624c48de5ca896ab438063
 - https://sepolia.basescan.org/tx/0x6de85cf23912f87f0283bbf97f127b0b30ddccc76c1671f5aac6e35c5e1c5148
### AI Game Fee Collection
 - https://sepolia.basescan.org/tx/0xd5c99b3feb997fa6f42b4cdd1c748fffc81a268822b9f90bffade22f48cd6326
 - https://sepolia.basescan.org/tx/0x04085f7ccfe58754a9d3bf0e531617b2c98fcff7d8f12c796cbe73c99bf859e6
 - https://sepolia.basescan.org/tx/0xa37cc7d0cf2089583fdce9aeeaec837cb24054530fba21de3671c8c3bdb44e7f

## Contact

For any inquiries, please reach out through email:  infantsamchris@gmail.com

## Acknowledgments
- Base Network for blockchain infrastructure
- Nillion for SecretVault Data Storage And the lightweight decentralized AI
- Coinbase Developer Platform for CDP Wallet intergation through Agentkit
- OpenAI & LangChain for setting the base for AI capabilities
