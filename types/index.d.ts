/** Types for webhookcage. No external type dependencies. */

export type WebhookCageErrorCode =
  | 'INVALID_ARGUMENT'
  | 'INVALID_BODY'
  | 'INVALID_SECRET'
  | 'MISSING_HEADER'
  | 'INVALID_HEADER'
  | 'INVALID_SIGNATURE'
  | 'SIGNATURE_MISMATCH'
  | 'TIMESTAMP_MISSING'
  | 'TIMESTAMP_INVALID'
  | 'TIMESTAMP_OUT_OF_TOLERANCE'
  | 'REPLAYED_DELIVERY'
  | 'UNKNOWN_PROVIDER'
  | 'SSRF_REJECTED';

export declare const ERROR_CODES: Readonly<Record<WebhookCageErrorCode, WebhookCageErrorCode>>;

export declare class WebhookCageError extends Error {
  readonly name: 'WebhookCageError';
  readonly code: WebhookCageErrorCode;
  readonly reason: string;
  readonly details?: Readonly<Record<string, unknown>>;
  constructor(code: WebhookCageErrorCode, reason: string, details?: Record<string, unknown>);
  toJSON(): { name: string; code: WebhookCageErrorCode; message: string; details?: Readonly<Record<string, unknown>> };
}

export type RawBody = string | Uint8Array;
export type HeaderInput =
  | Readonly<Record<string, string | readonly string[]>>
  | ReadonlyMap<string, string | readonly string[]>
  | { get(name: string): unknown; forEach(callback: (value: string, key: string) => void): void };

export type HmacAlgorithm = 'sha256' | 'sha512' | 'hmac-sha256' | 'hmac-sha512';
export type SignatureEncoding = 'hex' | 'base64';
export type ProviderName = 'github' | 'stripe' | 'slack' | 'standard-webhooks';
export type Milliseconds = number;

export interface HmacOptions {
  readonly algorithm?: HmacAlgorithm;
  readonly encoding?: SignatureEncoding;
}

export interface SignatureMatch {
  readonly secretIndex: number;
  readonly signatureIndex: number;
  readonly algorithm: string;
}

export interface HmacVerificationResult {
  readonly secretIndex: number;
  readonly matchedSignatures: readonly SignatureMatch[];
}

export interface VerifyOptions {
  readonly secret?: string | Uint8Array;
  readonly secrets?: readonly (string | Uint8Array)[];
  readonly now?: Milliseconds | (() => Milliseconds);
  readonly toleranceSeconds?: number;
  readonly futureSkewSeconds?: number;
  readonly replayStore?: ReplayStore;
  readonly requireReplay?: boolean;
}

export interface VerificationResult {
  readonly valid: true;
  readonly provider: ProviderName;
  readonly algorithm: 'sha256';
  readonly timestamp: Milliseconds | null;
  readonly deliveryId: string | null;
  readonly replayKey: string | null;
  readonly secretIndex: number;
  readonly matchedSignatures: readonly SignatureMatch[];
  readonly replayProtected: boolean;
}

export interface ReplayStore {
  checkAndRecord(key: string): boolean;
}

export declare class MemoryReplayStore implements ReplayStore {
  readonly ttlMs: number;
  readonly maxEntries: number;
  constructor(options?: { ttlMs?: number; maxEntries?: number; now?: Milliseconds | (() => Milliseconds) });
  prune(): void;
  checkAndRecord(key: string): boolean;
  size(): number;
}

export interface TimestampFreshness {
  readonly timestampMs: Milliseconds;
  readonly ageMs: number;
  readonly toleranceSeconds: number;
  readonly futureSkewSeconds: number;
}

export interface StandardWebhookSignatureHeaders {
  readonly 'webhook-id': string;
  readonly 'webhook-timestamp': string;
  readonly 'webhook-signature': string;
}

export interface StripeSignatureParts {
  readonly timestamp: string;
  readonly signatures: readonly string[];
}

export declare const VERSION: '1.0.0';

export declare function redactInput(value: unknown): string;
export declare function normalizeHeaders(headers: unknown): Map<string, string[]>;
export declare function requireSingleHeader(headers: ReadonlyMap<string, readonly string[]>, name: string): string;
export declare function optionalSingleHeader(headers: ReadonlyMap<string, readonly string[]>, name: string): string | null;

export declare function normalizeBody(body: RawBody): Uint8Array;
export declare function normalizeSecrets(secret?: string | Uint8Array, secrets?: readonly (string | Uint8Array)[]): readonly Uint8Array[];
export declare function normalizeAlgorithm(algorithm: string): 'sha256' | 'sha512';
export declare function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean;
export declare function decodeSignature(text: string, encoding: SignatureEncoding, algorithm: HmacAlgorithm): Uint8Array;
export declare function hmacDigest(secret: string | Uint8Array, payload: RawBody, algorithm: HmacAlgorithm): Uint8Array;
export declare function signHmac(secret: string | Uint8Array, payload: RawBody, options?: HmacOptions): string;
export declare function verifyHmacSignatures(
  presentedSignatures: readonly string[],
  secrets: readonly (string | Uint8Array)[],
  payload: RawBody,
  options?: HmacOptions
): HmacVerificationResult;
export declare function sha256Hex(text: string | Uint8Array): string;

export declare function resolveNow(now?: Milliseconds | (() => Milliseconds)): Milliseconds;
export declare function parseTimestampSeconds(value: string): Milliseconds;
export declare function assertTimestampFresh(timestampText: string, options?: {
  readonly now?: Milliseconds | (() => Milliseconds);
  readonly toleranceSeconds?: number;
  readonly futureSkewSeconds?: number;
}): TimestampFreshness;
export declare function deliveryKey(provider: string, identifier: string | null): string | null;
export declare function recordDelivery(store: ReplayStore | undefined, key: string | null): void;

export declare function signGitHub(body: RawBody, secret: string | Uint8Array): string;
export declare function verifyGitHub(body: RawBody, headers: HeaderInput, options?: VerifyOptions): Omit<VerificationResult, 'replayProtected'>;
export declare function signStripe(body: RawBody, secret: string | Uint8Array, timestamp?: number): string;
export declare function parseStripeSignature(header: string): StripeSignatureParts;
export declare function verifyStripe(body: RawBody, headers: HeaderInput, options?: VerifyOptions): Omit<VerificationResult, 'replayProtected'>;
export declare function signSlack(body: RawBody, secret: string | Uint8Array, timestamp?: number): string;
export declare function verifySlack(body: RawBody, headers: HeaderInput, options?: VerifyOptions): Omit<VerificationResult, 'replayProtected'>;
export declare function signStandardWebhooks(body: RawBody, secret: string | Uint8Array, messageId: string, timestamp?: number): StandardWebhookSignatureHeaders;
export declare function parseStandardWebhookSignatures(header: string): readonly string[];
export declare function verifyStandardWebhooks(body: RawBody, headers: HeaderInput, options?: VerifyOptions): Omit<VerificationResult, 'replayProtected'>;

export declare const providerVerifiers: Readonly<Record<ProviderName, (body: RawBody, headers: HeaderInput, options?: VerifyOptions) => Omit<VerificationResult, 'replayProtected'>>>;
export declare const providerSigners: Readonly<{
  github: typeof signGitHub;
  stripe: typeof signStripe;
  slack: typeof signSlack;
  'standard-webhooks': typeof signStandardWebhooks;
}>;
export declare function listProviders(): readonly ProviderName[];
export declare function verifyWebhook(provider: string, body: RawBody, headers: HeaderInput, options?: VerifyOptions): VerificationResult;
export declare function signWebhook(provider: string, body: RawBody, secret: string | Uint8Array, options?: { timestamp?: number; messageId?: string }): string | StandardWebhookSignatureHeaders;
export declare function createVerifier(provider: string, defaultOptions?: VerifyOptions): Readonly<{
  provider: ProviderName;
  verify(body: RawBody, headers: HeaderInput, options?: VerifyOptions): VerificationResult;
}>;

export type DeliveryErrorCode =
  | 'INVALID_URL'
  | 'INVALID_IP'
  | 'INVALID_HOST'
  | 'UNSAFE_SCHEME'
  | 'USERINFO_FORBIDDEN'
  | 'PRIVATE_IP'
  | 'DNS_REBIND'
  | 'HOST_DENIED'
  | 'HOST_NOT_ALLOWED'
  | 'PORT_FORBIDDEN'
  | 'PIN_MISMATCH'
  | 'INPUT_TOO_LARGE'
  | 'UNSUPPORTED_IDNA'
  | 'RESOLUTION_FAILED';

export interface DeliveryHostPolicy {
  readonly allow?: readonly string[];
  readonly deny?: readonly string[];
  readonly allowPublicSuffix?: boolean;
}

export interface DeliveryValidationOptions {
  readonly allowedSchemes?: readonly string[];
  readonly allowUserinfo?: boolean;
  readonly allowedPorts?: readonly number[] | 'default-only' | 'any';
  readonly hostPolicy?: DeliveryHostPolicy;
  readonly maxInputLength?: number;
  readonly idna?: 'ascii-only' | 'allow-unicode';
  readonly denyCidrs?: readonly string[];
  readonly allowCidrs?: readonly string[];
}

export interface DeliveryValidationSuccess {
  readonly ok: true;
  readonly url: URL;
  readonly normalized: string;
  readonly hostname: string;
  readonly port: number | undefined;
  readonly ipClass: string;
  readonly normalizedIp: string | null;
}

export interface DeliveryValidationFailure {
  readonly ok: false;
  readonly code: DeliveryErrorCode;
  readonly detail: string;
  readonly input?: string;
}

export type DeliveryValidationResult = DeliveryValidationSuccess | DeliveryValidationFailure;

export interface ResolvedDeliveryOptions extends DeliveryValidationOptions {
  readonly pinnedIp?: string;
  readonly previousIps?: readonly (string | { address: string })[];
}

export interface ResolvedDeliveryResult {
  readonly ok: boolean;
  readonly code?: DeliveryErrorCode;
  readonly detail?: string;
  readonly url?: string;
  readonly hostname?: string;
  readonly port?: number;
  readonly resolvedIps: readonly string[];
  readonly pinnedIp?: string | null;
  readonly pinned: boolean;
  readonly everyResolvedIpVerified?: boolean;
}

export interface DeliveryGuard {
  validate(input: string): DeliveryValidationResult;
  assert(input: string): DeliveryValidationSuccess;
  isPublicHostname(hostname: string): boolean;
  readonly options: Readonly<DeliveryValidationOptions>;
}

export declare function validateDeliveryUrl(input: unknown, options?: DeliveryValidationOptions): DeliveryValidationResult;
export declare function auditDeliveryUrl(input: unknown, options?: DeliveryValidationOptions): DeliveryValidationResult;
export declare function assertSafeDeliveryUrl(input: unknown, options?: DeliveryValidationOptions): DeliveryValidationSuccess;
export declare function auditResolvedDeliveryTarget(
  input: unknown,
  resolvedIps: readonly (string | { address: string })[],
  options?: ResolvedDeliveryOptions
): ResolvedDeliveryResult;
export declare function createDeliveryGuard(options?: DeliveryValidationOptions): DeliveryGuard;
export declare function normalizeDeliveryHost(input: unknown): string | null;

export declare function validateUrl(input: unknown, options?: DeliveryValidationOptions): DeliveryValidationResult;
export declare function auditUrl(input: unknown, options?: DeliveryValidationOptions): DeliveryValidationResult;
export declare function assertSafeUrl(input: unknown, options?: DeliveryValidationOptions): DeliveryValidationSuccess;
export declare function auditResolvedTarget(
  input: unknown,
  resolvedIps: readonly (string | { address: string })[],
  options?: ResolvedDeliveryOptions
): ResolvedDeliveryResult;
export declare function createGuard(options?: DeliveryValidationOptions): DeliveryGuard;
export declare function normalizeHost(input: unknown): string | null;
export declare function isPublicHostname(hostname: string, options?: DeliveryValidationOptions): boolean;
export declare function auditIp(input: unknown): Readonly<{ ok: boolean; code: string; detail: string; classification: string; normalized: string | null }>;
export declare function parseIpv4(host: string): string | null;
export declare function parseIpv6(host: string): number[] | null;
export declare function normalizeIp(host: string): string | null;
export interface ParsedIpv4Cidr {
  readonly family: 4;
  readonly value: number;
  readonly bits: number;
}

export interface ParsedIpv6Cidr {
  readonly family: 6;
  readonly groups: readonly number[];
  readonly bits: number;
}

export declare function parseCidr(cidr: string): ParsedIpv4Cidr | ParsedIpv6Cidr | null;
export declare function cidrContains(cidr: string, address: string): boolean;
export declare function formatIpv6(groups: readonly number[]): string | null;
export declare function ipv4ToUint32(ip: string): number | null;
