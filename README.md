# UO — Decentralized Social Network

A blockchain-based social media dApp where posts, likes, comments, and user profiles live on an Ethereum smart contract, with media stored on IPFS. It also bundles a peer-to-peer chat app and an admin/monitoring dashboard.

## What It Is

UO is a "Dwitter"-style microblogging platform. Instead of a central database, user activity is written to a Solidity smart contract on Ethereum and read back through the browser via MetaMask and Web3.js. Uploaded images are pinned to IPFS rather than a traditional server. A separate real-time chat module and an admin dashboard round out the project.

This repository is made up of a few independent pieces:

### Ethereum smart contract (`contracts/`, `migrations/`, `build/`)
- `dwitter.sol` — the core contract: create posts ("dweets"), comment, like, and manage user profiles, using a `SafeMath` library for arithmetic safety.
- `Migrations.sol` — standard Truffle migration contract.
- Deployed and tested with [Truffle](https://trufflesuite.com/) (`truffle-config.js`, `test/dwitter.test.js`).

### Web dApp frontend (`src/`)
- `index.html` — the main feed. Connects the user's MetaMask wallet, loads their on-chain profile, and lets them post dweets, like, and comment. Media is uploaded to IPFS via `ipfs-http-client`.
- `admin.html` — an admin / monitoring dashboard (reports, advertisements, and data views), built on the Argon dashboard template.
- `app.js` / `app2.js` — vanilla JavaScript + jQuery driving the feed and the admin views, using Web3.js to talk to the contract.
- `public/` — static assets, stylesheets, and the bundled `web3.min.js`.

### Real-time chat (`UOchatmessaging/`)
- A separate [Svelte](https://svelte.dev/) app for peer-to-peer chat, built on the [GUN](https://gun.eco/) decentralized graph database. Includes login, chat, and message components, and is configured for Firebase Hosting deployment.

### Rust server (`RustServer/`)
- `server.rs` — an experimental thread-pool based server written in Rust.

### Node server (`server.js`)
- A small Express server that serves the `src/` frontend as static files.

## Tech Stack

- **Smart contracts:** Solidity, Truffle, SafeMath
- **Blockchain / web3:** Ethereum, Web3.js, MetaMask, IPFS (Infura)
- **Frontend:** HTML, CSS, JavaScript (jQuery), Bootstrap
- **Chat:** Svelte, GUN, Firebase Hosting
- **Backend / tooling:** Node.js, Express, Rust

## Running It

### Frontend dApp
The frontend is a web3 dApp — it needs the [MetaMask](https://metamask.io/) browser extension and a deployed copy of the smart contract to be fully functional.

```bash
npm install
npm start          # serves src/ via Express at http://localhost:3000
```

To just view the markup and styling without a wallet, you can also open `src/index.html` directly in a browser (contract-backed features will be inactive).

### Smart contract (optional, for full functionality)
```bash
npm install -g truffle
truffle compile
truffle migrate            # deploy to your configured network
truffle test               # run contract tests
```

Network and wallet settings live in `truffle-config.js`.

### Chat app
```bash
cd UOchatmessaging
npm install
npm run dev                # local dev server
```

## Screenshots

_Screenshots coming soon._

## Credit

Based on the [Decentralized_Social_Media](https://github.com/mbcse/Decentralized_Social_Media) project. Licensed under the MIT License (see `LICENSE`).
