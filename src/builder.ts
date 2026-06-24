// A generic disclosure builder - so a non-OpenSolvency adopter can construct a
// valid AgentDisclosure without hand-writing the literal and getting a field shape
// wrong. The reference implementation populates these structures from a live gate;
// this is the manual path for everyone else. build() validates against the schema,
// so a malformed disclosure fails here, not at a counterparty.

import { signDisclosure, sha256Hex, type AgentKeyPair } from "./attestation.ts";
import {
  AgentDisclosureSchema,
  DISCLOSURE_SCHEMA_VERSION,
  parseDisclosure,
  type AgentDisclosure,
  type CapitalEnvelope,
  type Constitution,
  type DeploymentHistory,
  type ModelIdentity,
  type OperatorIdentity,
  type RedTeamAttestation,
  type SignedDisclosure,
  type SystemPromptFingerprint,
  type Tool,
  type ToolInventory,
} from "./schema.ts";

export interface BuildOptions {
  agentKey: AgentKeyPair;
  /** ISO-8601 issuedAt; validUntil = now + the configured window */
  now: string;
  nonce: string;
}

/** Fluent builder for an AgentDisclosure. Each setter returns `this`. The identity
 *  fields (version/disclosureId/agentId/issuedAt/validUntil) are filled at build(). */
export class DisclosureBuilder {
  #systemPrompt?: SystemPromptFingerprint;
  #constitution?: Constitution;
  #tools?: ToolInventory;
  #capital?: CapitalEnvelope;
  #operator?: OperatorIdentity;
  #history?: DeploymentHistory;
  #redTeam?: RedTeamAttestation;
  #model?: ModelIdentity;
  #validForMs = 24 * 60 * 60 * 1000;

  /** Fingerprint the composed system prompt (sha256 of the text). */
  systemPrompt(text: string, promptVersion?: string): this {
    this.#systemPrompt = { algorithm: "sha256", digest: sha256Hex(text), promptVersion };
    return this;
  }

  /** Declare the operating constitution; `digest` is computed if omitted. */
  constitution(c: Omit<Constitution, "digest"> & { digest?: string }): this {
    const { hardConstraints, parameters, enforced, enforcementEvidence } = c;
    const digest = c.digest ?? sha256Hex(JSON.stringify({ hardConstraints, parameters, enforced }));
    this.#constitution = { hardConstraints, parameters, enforced, enforcementEvidence, digest };
    return this;
  }

  /** Declare the tool inventory + permission boundaries. */
  tools(tools: Tool[], valuePath?: string): this {
    this.#tools = { tools, valuePath };
    return this;
  }

  /** Declare the capital + risk envelope. */
  capital(c: CapitalEnvelope): this {
    this.#capital = c;
    return this;
  }

  /** Declare the operator identity + deniability boundary. */
  operator(o: OperatorIdentity): this {
    this.#operator = o;
    return this;
  }

  /** Declare the cumulative deployment history summary. */
  history(h: DeploymentHistory): this {
    this.#history = h;
    return this;
  }

  /** Declare red-team pass/fail attestations (optional). */
  redTeam(r: RedTeamAttestation): this {
    this.#redTeam = r;
    return this;
  }

  /** Declare the model identity (optional). */
  model(m: ModelIdentity): this {
    this.#model = m;
    return this;
  }

  /** Set the freshness window length in milliseconds (default 24h). */
  validFor(ms: number): this {
    this.#validForMs = ms;
    return this;
  }

  /** Assemble + validate the disclosure. Throws if a required field group is unset
   *  or the assembled document fails the schema. */
  build(opts: BuildOptions): AgentDisclosure {
    if (!this.#systemPrompt) throw new Error("systemPrompt is required");
    if (!this.#constitution) throw new Error("constitution is required");
    if (!this.#tools) throw new Error("tools is required");
    if (!this.#capital) throw new Error("capital is required");
    if (!this.#operator) throw new Error("operator is required");
    if (!this.#history) throw new Error("history is required");

    const issuedAt = opts.now;
    const validUntil = new Date(new Date(opts.now).getTime() + this.#validForMs).toISOString();
    const agentId = opts.agentKey.publicKeyHex;

    const draft: AgentDisclosure = {
      version: DISCLOSURE_SCHEMA_VERSION,
      disclosureId: `disc_${sha256Hex(`${agentId}:${opts.nonce}:${issuedAt}`).slice(0, 16)}`,
      agentId,
      issuedAt,
      validUntil,
      nonce: opts.nonce,
      systemPrompt: this.#systemPrompt,
      constitution: this.#constitution,
      tools: this.#tools,
      capital: this.#capital,
      operator: this.#operator,
      history: this.#history,
      redTeam: this.#redTeam,
      model: this.#model,
    };

    return parseDisclosure(AgentDisclosureSchema.parse(draft));
  }

  /** Build, then sign into a SignedDisclosure envelope. */
  buildAndSign(opts: BuildOptions): SignedDisclosure {
    return signDisclosure(this.build(opts), opts.agentKey);
  }
}
