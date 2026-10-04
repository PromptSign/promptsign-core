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

/** Every trust root the verifier accepts: the pinned public root, then the
 * user's named roots from `~/.promptsign/trust/roots`. */
export function trustRoots(): RegistryRoot[];

/** The wrapped promptsign-core version. */
export function coreVersion(): string;

export interface TrustRootInfo {
  /** Directory holding fulcio.pem and rekor.pub. */
  dir: string;
  /**
   * Why that directory: an explicit `PROMPTSIGN_TRUST_DIR`, a `PROMPTSIGN_HOME`
   * that takes precedence over the package's own copy, the root `bundled` with
   * this package, or the core's default location under the user's home.
   */
  source: 'PROMPTSIGN_TRUST_DIR' | 'PROMPTSIGN_HOME' | 'bundled' | 'promptsign-home-default';
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
