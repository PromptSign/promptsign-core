// Type definitions for @promptsign/verify. The verifier is the same audited
// promptsign-core the CLI uses; these results mirror `promptsign … --json`.

export interface VerifyOpts {
  /** Explicit policy file path (defaults to the CLI's resolution order). */
  policyPath?: string;
  /** Do not write TOFU pins as a side effect of verification. */
  noPinUpdates?: boolean;
}

export interface Finding {
  level: 'error' | 'warn' | 'info';
  message: string;
}

export interface VerifyResult {
  target: string;
  policySource: string;
  name: string;
  version?: string;
  kind?: string;
  identity: string | null;
  issuer?: string;
  keyid: string | null;
  /** Rekor log integration time (Unix seconds) for keyless signatures — the
   * authenticated moment the signature was witnessed. Absent for local-key
   * signatures and unsigned/failed targets. */
  integratedTime?: number;
  /** Signature format: "promptsign", or "oms" for an OpenSSF Model Signing
   * bundle (skill.oms.sig, model.sig). Absent when unsigned. */
  format?: 'promptsign' | 'oms';
  /** Trust root the signer chained to (keyless and certificate mode). */
  root?: string;
  signed: boolean;
  action: 'pass' | 'warn' | 'fail';
  findings: Finding[];
  /** Verified approvals of the artifact's content (spec/09), present when a
   * policy rule for it requires approvals and some verified. */
  approvals?: Approval[];
  /** What the decision log records beyond the verdict. Not enumerable, so
   * `JSON.stringify(result)` matches `promptsign verify --json`; pass the
   * result itself to `logDecisions`. */
  readonly evidence: Evidence;
}

export interface Approval {
  /** The approver: a certificate's SAN, or its subject DN in certificate mode. */
  identity: string;
  /** OIDC issuer, or `x509:sha256:<root fingerprint>` in certificate mode. */
  issuer: string;
  /** Trust root the approval chained to. */
  root: string;
  /** When the approver signed, in Unix seconds, if the signature proves it. */
  signedAt?: number;
}

export interface Evidence {
  /** `sha256:<hex>` of the signed payload. */
  payloadDigest?: string;
  /** The policy layer and rule that decided. */
  rule?: { layer: 'managed' | 'user' | 'project'; pattern: string; action: string };
  /** Absent when no revocation feed applies. */
  revocation?: 'clear' | 'revoked' | 'stale' | 'unavailable';
}

export interface KeylessInfo {
  identity: string;
  issuer: string;
  keyid: string;
  /** Trust root the certificate chained to. */
  root: string;
}

export interface RegistryRoot {
  name: string;
  /** "keyless": Fulcio CA plus transparency log. "certificate": a CA only,
   * checked at the current time. */
  kind: 'keyless' | 'certificate';
  /** Hex SHA-256 of the anchor certificate. */
  fingerprint: string;
  subject: string;
  /** From the machine's managed trust directory, which users cannot change. */
  managed: boolean;
  /** For a trust bundle's root (named `<bundle>/<root>`), the bundle's
   * expiry (RFC 3339). Past it, the bundle is stale until `promptsign trust
   * fetch` refreshes it. */
  expires?: string;
}

/** Verify one target (directory or file). Mirrors `promptsign verify --json`. */
export function verify(target: string, opts?: VerifyOpts): VerifyResult;

/** Verify a tree of roots. Mirrors `promptsign verify-tree --json`. */
export function verifyTree(roots: string[], opts?: VerifyOpts): VerifyResult[];

/** Offline keyless verification of a bundle (object or JSON string).
 * Throws on any verification failure. */
export function verifyKeyless(bundle: object | string): KeylessInfo;

/** The user's policy (like `promptsign policy show`). A project's own
 * `.promptsign/policy.json` in `dir` can only tighten it. */
export function policyShow(dir: string): unknown;

export interface PolicyLayer {
  /** "managed" (the machine's, set by an administrator), "user", or
   * "project" (tighten only). Over a managed policy the user's tightens only. */
  layer: 'managed' | 'user' | 'project';
  /** The file the layer came from, or "(built-in default)". */
  source: string;
  /** The policy JSON as written. */
  policy: unknown;
}

/** Every policy layer that applies in `dir`, in evaluation order. */
export function policyLayers(dir: string): PolicyLayer[];

/** True when hooks should fail closed: PROMPTSIGN_STRICT=1, or `strict: true`
 * in the managed or the user policy. */
export function strictMode(): boolean;

/** Every trust root the verifier accepts: the built-in root, the managed
 * roots and bundles, then the user's named roots from
 * `~/.promptsign/trust/roots` and installed trust bundles. */
export function trustRoots(): RegistryRoot[];

/** The wrapped promptsign-core version. */
export function coreVersion(): string;

export type LogEntry =
  | { result: VerifyResult; decision?: 'allow' | 'block' }
  | { unresolved: { name: string; message: string }; decision: 'allow' | 'block' }
  | { error: { name?: string; target?: string; message: string }; decision?: 'allow' | 'block' };

export interface LogInput {
  /** "claude", "codex" or "openclaw" for a hook. */
  harness?: string;
  /** The hook event, e.g. "PreToolUse" or "SessionStart". */
  event: string;
  /** A file to log to beside the policies' logs. */
  decisionLog?: string;
  /** The policy file `verify` was given, if any. */
  policyPath?: string;
  entries: LogEntry[];
}

/** Append decision log records (spec/08) to the logs the managed and the user
 * policy turn on and to `decisionLog`. A result may carry the action and
 * findings the caller settled on. Returns the logs that could not be written;
 * a failed write never throws. */
export function logDecisions(input: LogInput): string[];

export interface TrustRootInfo {
  /** Directory holding fulcio.pem and rekor.pub. */
  dir: string;
  /**
   * Why that directory: the machine's `managed` trust directory, the user's
   * home because the managed policy sets `lock_env`, an explicit
   * `PROMPTSIGN_TRUST_DIR`, a `PROMPTSIGN_HOME` that takes precedence over the
   * package's own copy, the root `bundled` with this package, or the core's
   * default location under the user's home.
   */
  source:
    | 'managed'
    | 'lock_env'
    | 'PROMPTSIGN_TRUST_DIR'
    | 'PROMPTSIGN_HOME'
    | 'bundled'
    | 'promptsign-home-default';
}

/**
 * The Sigstore trust root keyless verification will use, and why.
 *
 * This package pins its own copy in `trust/`, so verification works offline on a
 * machine that has never run `promptsign trust fetch`. On the first call to
 * `verify`, `verifyTree` or `verifyKeyless` that copy is selected by setting
 * `process.env.PROMPTSIGN_TRUST_DIR` — the core reads the directory from the
 * environment. A `PROMPTSIGN_TRUST_DIR` or `PROMPTSIGN_HOME` the host already
 * set is never overridden, so an operator's own (or private) root wins.
 */
export function trustRoot(): TrustRootInfo;
