---
name: attack-web3-audit
description: "Review authorized Web3 applications for contract trust, wallet flows, and integration risks"
category: "application-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [web3, blockchain, smart-contracts, wallet, dapp]
tech_stack: [ethereum, solidity, walletconnect, javascript]
prerequisites:
  - "Explicit authorization for the DApp, contracts, testnet, and any connected services"
  - "Test wallet and testnet/fork environment; no real funds"
chains_with: [attack-web-recon, attack-api-misconfig, attack-llm-security, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/web3-audit/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/web3-audit/SKILL.md"
---

# Web3 Application Security Review

## When to use

Use when reviewing an authorized decentralized application, smart-contract integration, wallet connection, signing flow, or blockchain-facing API.

## Safety gate

Use a local fork or testnet and test wallets. Do not send real funds, interact with mainnet contracts in a state-changing way, or expose seed phrases/private keys. Contract audit scope must be explicit.

## Procedure

1. Map the DApp frontend, wallet connector, RPC provider, backend APIs, contract addresses, chain IDs, and deployment provenance.
2. Verify contract source and deployed bytecode correspondence where available; record compiler and network details.
3. Review transaction construction, chain switching, spender/recipient addresses, signature messages, and approval scopes.
4. Check whether the UI clearly presents what is signed and whether server-side/backend assumptions match on-chain permissions.
5. Inspect authorization, upgradeability, admin roles, pause controls, oracle dependencies, and external calls in contract source or audit artifacts.
6. Use static analysis and tests on a local fork/testnet; avoid live mainnet state changes.
7. Assess front-end supply-chain and API boundaries separately from smart-contract logic.
8. Record the exact contract/network and a minimal reproducible test case with no private keys or seed phrases.

## Pitfalls

- A contract address or verified source does not imply safety.
- A testnet issue may not reproduce on the deployed mainnet state.
- Never store private keys or seed phrases in evidence.
- A wallet prompt is not proof of a malicious transaction without inspecting the actual call.

## Verification

Identify the chain, contract/version, preconditions, tested invariant, transaction or trace on the test environment, and impact. Clearly separate static findings from runtime-confirmed behavior.
