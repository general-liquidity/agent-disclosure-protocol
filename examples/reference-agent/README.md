# ADP Reference Agent

A deployable, runnable reference agent for the Agent Disclosure Protocol. It is a
single `node:http` service that exposes its **own** agent surface (a signed disclosure
plus a live challenge-response handshake) **and** verifies a counterparty before it
pays. Two of these pointed at each other demonstrate the full "adopt ADP" loop over a
real socket: each agent verifies the other before a single unit of value moves.

This makes the protocol concrete. To adopt ADP, an agent does exactly what this service
does: serve `/.well-known/agent-disclosure`, answer the handshake to prove live key
possession, and run `guardSettlement` / `verifyCounterparty` in front of its rail.

## Endpoints

| Method + path | What it does |
|---|---|
| `GET /.well-known/agent-disclosure` | This agent's freshly signed `SignedDisclosure`. The `agentId` is the ed25519 public key, so a verifier checks it with no shared secret and no registry. |
| `POST /agent-disclosure/respond` | The live handshake. Body is a `Challenge`; the response signs the nonce bound to the agent's current audit head, proving it holds the signing key right now. |
| `GET /health` | `{ ok: true, agentId, operatorId }`. |
| `POST /pay` | Verify-before-pay gate. Body `{ payeeBaseUrl, amount }`. The agent runs `guardSettlement` against the payee with its configured policy and only "settles" if the payee's disclosure clears; otherwise it refuses with reasons. No real money moves - this is the gate demo. |

`/pay` responses:

- settled: `200 { settled: true, amount, payeeBaseUrl, checks }`
- refused: `402 { settled: false, refused: true, reasons, payeeBaseUrl }` (fails closed on any transport, parse, or policy failure)
- bad request: `400 { settled: false, error }`

## Run with Node

From the repo root:

```bash
npm ci
PORT=8800 node --import tsx examples/reference-agent/server.ts
```

```bash
curl http://localhost:8800/health
curl http://localhost:8800/.well-known/agent-disclosure
```

`PORT` defaults to `8800`.

## Run with Docker

From the repo root:

```bash
docker build -f examples/reference-agent/Dockerfile -t adp-reference-agent .
docker run --rm -p 8800:8800 adp-reference-agent
curl http://localhost:8800/health
```

Override the port with `-e PORT=9000 -p 9000:9000`.

## Two agents verifying each other (curl)

Start two reference agents on different ports, then have agent A verify-and-pay agent B
over a real socket:

```bash
# terminal 1
PORT=8810 node --import tsx examples/reference-agent/server.ts
# terminal 2
PORT=8811 node --import tsx examples/reference-agent/server.ts

# terminal 3: A verifies B's disclosure + live handshake, then settles
curl -s -X POST http://localhost:8810/pay \
  -H 'content-type: application/json' \
  -d '{"payeeBaseUrl":"http://localhost:8811","amount":25}'
# -> {"settled":true,"amount":25,"payeeBaseUrl":"http://localhost:8811","checks":{...}}

# B verifies A right back (mutual)
curl -s -X POST http://localhost:8811/pay \
  -H 'content-type: application/json' \
  -d '{"payeeBaseUrl":"http://localhost:8810","amount":25}'
# -> {"settled":true,...}

# An unreachable payee is refused before any value moves (fail closed)
curl -s -X POST http://localhost:8810/pay \
  -H 'content-type: application/json' \
  -d '{"payeeBaseUrl":"http://localhost:1","amount":25}'
# -> {"settled":false,"refused":true,"reasons":["disclosure unreachable: fetch failed"],...}
```

## Configuring the gate

`startReferenceAgent(opts)` (exported from `server.ts`) drives the agent in-process and
takes a `payPolicy` - the `VerificationPolicy` (minus `now`, which is supplied per
request) the agent applies to every payee. Tighten it to refuse more counterparties:

```ts
import { startReferenceAgent } from "./server.ts";

// Refuses any payee without a red-team attestation, before value moves.
const agent = await startReferenceAgent({
  port: 8800,
  operatorId: "agent-a",
  payPolicy: { requireEnforcedConstitution: true, requireAuditAnchor: true, requireRedTeam: true },
});
```

`handshakeSkewMs` (default 2000ms) sets the clock-skew + round-trip tolerance when
checking a payee's freshly-signed challenge response; raise it for high-latency or
poorly-synced deployments.

## Smoke test

`smoke.test.ts` starts two real agents in-process and exercises the full loop: A pays B
under a met policy (settles), refuses B under a stricter policy B cannot meet, fails
closed against an unreachable payee, mutual A<->B settlement, and the `/health` +
disclosure endpoints.

```bash
node --import tsx --test examples/reference-agent/smoke.test.ts
```
