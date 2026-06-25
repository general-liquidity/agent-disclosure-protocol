import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createValidationRegistryClient,
  VALIDATION_REGISTRY_ABI,
} from "../src/erc8004Validation.ts";

async function viemAvailable(): Promise<boolean> {
  try {
    await import("viem");
    return true;
  } catch {
    return false;
  }
}

const HAS_VIEM = await viemAvailable();
if (!HAS_VIEM) {
  console.log(
    "[erc8004Validation.test] viem not installed - skipping validation eth_call tests. " +
      "Install with `npm install viem` to exercise the on-chain validation reads.",
  );
}

const REGISTRY = "0x00000000000000000000000000000000000a1111";
const VALIDATOR = "0x2222222222222222222222222222222222222222";
const IDENTITY = "0x3333333333333333333333333333333333333333";
const REQ_HASH = `0x${"ab".repeat(32)}`;
const RESP_HASH = `0x${"cd".repeat(32)}`;
const AGENT_ID = 7n;

type StatusSeed = {
  validator: string;
  agentId: bigint;
  response: number;
  responseHash: string;
  tag: string;
  lastUpdate: bigint;
};

// A viem `custom` transport answering eth_call against the REAL Validation Registry ABI.
async function mockTransport(seed: {
  status?: StatusSeed;
  summary?: { count: bigint; avgResponse: number };
  agentValidations?: string[];
  validatorRequests?: string[];
  identityRegistry?: string;
}) {
  const { custom, decodeFunctionData, encodeAbiParameters } = await import("viem");

  return custom({
    async request({ method, params }: { method: string; params?: unknown }) {
      if (method === "eth_chainId") return "0x2105"; // Base
      if (method !== "eth_call") throw new Error(`unexpected JSON-RPC method ${method}`);

      const call = (params as [{ data: `0x${string}` }])[0];
      const decoded = decodeFunctionData({ abi: VALIDATION_REGISTRY_ABI, data: call.data });

      switch (decoded.functionName) {
        case "getValidationStatus": {
          const s = seed.status;
          return encodeAbiParameters(
            [
              { type: "address" },
              { type: "uint256" },
              { type: "uint8" },
              { type: "bytes32" },
              { type: "string" },
              { type: "uint256" },
            ],
            s
              ? [
                  s.validator as `0x${string}`,
                  s.agentId,
                  s.response,
                  s.responseHash as `0x${string}`,
                  s.tag,
                  s.lastUpdate,
                ]
              : [
                  "0x0000000000000000000000000000000000000000",
                  0n,
                  0,
                  `0x${"00".repeat(32)}` as `0x${string}`,
                  "",
                  0n,
                ],
          );
        }
        case "getSummary": {
          const sum = seed.summary ?? { count: 0n, avgResponse: 0 };
          return encodeAbiParameters(
            [{ type: "uint64" }, { type: "uint8" }],
            [sum.count, sum.avgResponse],
          );
        }
        case "getAgentValidations":
          return encodeAbiParameters(
            [{ type: "bytes32[]" }],
            [(seed.agentValidations ?? []) as `0x${string}`[]],
          );
        case "getValidatorRequests":
          return encodeAbiParameters(
            [{ type: "bytes32[]" }],
            [(seed.validatorRequests ?? []) as `0x${string}`[]],
          );
        case "getIdentityRegistry":
          return encodeAbiParameters(
            [{ type: "address" }],
            [(seed.identityRegistry ?? "0x0000000000000000000000000000000000000000") as `0x${string}`],
          );
        default:
          throw new Error(`unexpected validation function ${decoded.functionName}`);
      }
    },
  });
}

test("getValidationStatus decodes a validator's 0-100 score for a request", {
  skip: !HAS_VIEM,
}, async () => {
  const client = createValidationRegistryClient({
    registryAddress: REGISTRY,
    transport: await mockTransport({
      status: {
        validator: VALIDATOR,
        agentId: AGENT_ID,
        response: 100,
        responseHash: RESP_HASH,
        tag: "adp",
        lastUpdate: 1_700_000_000n,
      },
    }),
  });

  const status = await client.getValidationStatus(REQ_HASH);
  assert.equal(status.requestHash, REQ_HASH);
  assert.equal(status.validatorAddress, VALIDATOR.toLowerCase());
  assert.equal(status.agentId, AGENT_ID);
  assert.equal(status.response, 100);
  assert.equal(status.responseHash, RESP_HASH);
  assert.equal(status.tag, "adp");
  assert.equal(status.lastUpdate, 1_700_000_000n);
});

test("getValidationStatus maps an unanswered request to a zero record", {
  skip: !HAS_VIEM,
}, async () => {
  const client = createValidationRegistryClient({
    registryAddress: REGISTRY,
    transport: await mockTransport({}),
  });
  const status = await client.getValidationStatus(REQ_HASH);
  assert.equal(status.validatorAddress, null);
  assert.equal(status.response, 0);
  assert.equal(status.lastUpdate, 0n);
});

test("getSummary decodes count + mean score across an agent's validations", {
  skip: !HAS_VIEM,
}, async () => {
  const client = createValidationRegistryClient({
    registryAddress: REGISTRY,
    transport: await mockTransport({ summary: { count: 3n, avgResponse: 80 } }),
  });
  const summary = await client.getSummary(AGENT_ID, [VALIDATOR], "adp");
  assert.equal(summary.count, 3n);
  assert.equal(summary.avgResponse, 80);
});

test("getAgentValidations + getValidatorRequests decode request-hash arrays", {
  skip: !HAS_VIEM,
}, async () => {
  const client = createValidationRegistryClient({
    registryAddress: REGISTRY,
    transport: await mockTransport({
      agentValidations: [REQ_HASH],
      validatorRequests: [REQ_HASH, RESP_HASH],
    }),
  });
  assert.deepEqual(await client.getAgentValidations(AGENT_ID), [REQ_HASH]);
  assert.deepEqual(await client.getValidatorRequests(VALIDATOR), [REQ_HASH, RESP_HASH]);
});

test("getIdentityRegistry returns the bound Identity Registry address", {
  skip: !HAS_VIEM,
}, async () => {
  const client = createValidationRegistryClient({
    registryAddress: REGISTRY,
    transport: await mockTransport({ identityRegistry: IDENTITY }),
  });
  assert.equal(await client.getIdentityRegistry(), IDENTITY.toLowerCase());
});

test("createValidationRegistryClient requires an rpcUrl or a transport", () => {
  assert.throws(
    () => createValidationRegistryClient({ registryAddress: REGISTRY }),
    /rpcUrl or an injected transport/,
  );
});
