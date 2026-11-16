# PoC — Bull SDK `agree()`: amount inflated + conditions rewritten, no verification

## What it proves

The Bull SDK (`bull.mjs`, https://www.bull.family/sdk/bull.mjs) claims:
> "Safety: the API server is not trusted with your wallet. Every transaction
> it returns is checked before it is sent."

`agree()` breaks that promise. It only checks payer/payee from the
`AgreementCreated` event — NOT amount, asset, expiry, termsHash or
conditions — even though the event ALSO carries asset, amount, expiry and
termsHash, which the SDK has in its `AGR_ABI` but never compares.

A compromised/malicious API server can therefore inflate the locked amount
and rewrite the conditions to ones the attacker controls. The victim asked
to lock 500 USDC, attest by a neutral arbiter. The server returns steps for
5,000 USDC, attest by the ATTACKER. The SDK sends both steps with no error.
The attacker attests and releases the 5,000 USDC to themselves. The victim
loses 4,500 USDC more than agreed.

For ETH agreements the SDK's `#agreeCap` (105% + 0.05 ETH) limits the
inflation; for ERC-20 agreements the cap is only the 0.05 ETH fee and does
NOT bound the approved/locked token amount at all — the approve to the
Agreement contract is allowed up to 2**200-1.

Why this is NOT a duplicate of B-02 (`open()` / `buyerReceive`): B-02 is
about the BUYER's `open()` and the escrow deal. This is a different function
(`agree()`), a different victim (the payer of an agreement), a different
mechanism (amount inflation + condition rewrite), and fixing `open()` does
not touch `agree()`.

## Run (local only — no real funds, no mainnet, no Bull infrastructure)

```bash
# 1. Start Anvil (Foundry) on port 8545
anvil --port 8545 --chain-id 31337

# 2. Run (from this directory)
node run-poc.mjs
```

What happens:
1. Deploys `MockAgreement` (etched at the production Agreement address so
   the REAL SDK's guard accepts it) + MockUSDC.
2. Victim (payer) holds 5,000 USDC; asks to lock 500 USDC, attest by a
   neutral arbiter, payee = attacker (a contractor to pay).
3. Victim calls `bull.agree({...})` via the REAL SDK. The mock API returns
   inflated steps; the SDK sends approve + createAgreement with NO ERROR.
4. Attacker calls attest(id, 0) then release(id) on the agreement.

## Result (verified 16 Nov 2026)

```
SDK returned agreementId: 1 — NO ERROR, NO WARNING about the inflated amount / rewritten condition
on-chain agreement: amount 5000 USDC (victim agreed 500)
victim USDC balance after agree(): 0
attacker attested + released the agreement
victim USDC balance: 0
attacker USDC balance: 5000
EXPLOITED: victim agreed to lock 500 USDC but agree() locked 5,000 USDC with an attacker-controlled condition; attacker released all 5,000.
```

## Honest scope note

The real BullAgreement source is NOT verified anywhere (Sourcify and
Blockscout return no match), so this PoC uses a mock that implements the
DOCUMENTED Agreement semantics from https://www.bull.family/llms.txt (lock
funds, pay when all conditions are true, refund after expiry). The claim
proven here is the SDK's missing verification — demonstrated with the real
SDK sending the server's inflated steps — not the mock's internals. The
on-chain fund movement (approve + createAgreement pulling 5,000 tokens)
is real in the PoC; the release follows the documented condition model.

## Files

- `bull-sdk.mjs` — verbatim copy of https://www.bull.family/sdk/bull.mjs
  (sha256 `b8abb874115915485012abd954e9a0ea9951d66b42edb84e84583b5f52d52a0c`)
- `mock-api.mjs` — malicious mock Bull API (localhost only)
- `run-poc.mjs` — the PoC driver (real SDK + MockAgreement on Anvil)
- `chain/src/MockAgreement.sol` — mock implementing the documented semantics
- `chain/src/Mocks.sol` — MockERC20
- `poc-result.json` — machine-readable result of the last run

## Do NOT publish yet

This PoC is prepared for the Bull bug-bounty report form (whose PoC field
asks for a LINK). It must be published (repo) **only together with the
report submission**, after the user approves the draft — never before
(Bull's rules: no public disclosure until fixed). It contains no private
keys, no seed phrases, no real credentials: all wallets are throwaway keys
generated fresh on each run on a local Anvil chain.
