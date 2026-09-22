/**
 * Layer 4 connection matchers (caddy-l4) that CPM can generate.
 *
 * Kept free of DB/Caddy imports so it is usable from the model layer (input
 * validation), the Caddy config builder, and the UI (presets).
 */

export type L4RegexpMatcherConfig = {
  /** Match against the uppercase hex encoding of the bytes instead of the raw bytes. */
  hex: boolean;
  /** Number of bytes the connection must supply before the pattern is evaluated. */
  count: number;
};

/** caddy-l4 never buffers more than this while matching (layer4.MaxMatchingBytes). */
export const L4_REGEXP_MAX_COUNT = 16384;
export const L4_REGEXP_DEFAULT_COUNT = 8;
export const L4_REGEXP_MAX_PATTERN_LENGTH = 1024;

/**
 * MS-TDS PRELOGIN packet header (8 bytes), matched as uppercase hex:
 *
 *   12        Type    = 0x12 (PRELOGIN; also carries the TLS handshake for TDS 7.x)
 *   0[01]     Status  = 0x00 or 0x01 (EOM)
 *   0[0-9A-F]{3}  Length  < 0x1000, big-endian (includes the 8-byte header)
 *   0000      SPID    = 0
 *   [0-9A-F]{2}   PacketID (clients differ: 0 or 1; servers ignore it)
 *   00        Window  = 0
 *
 * A TLS record starts with 0x16, HTTP with an ASCII method, SSH with "SSH-",
 * HTTP/2 with "PRI ", so 0x12 plus the zeroed SPID/Window bytes is a very
 * specific signature. It does NOT match TDS 8.0 (Encrypt=Strict), which opens
 * with a TLS ClientHello.
 */
export const MSSQL_TDS_PRELOGIN_REGEXP: { pattern: string } & L4RegexpMatcherConfig = {
  pattern: "^12(00|01)0[0-9A-F]{3}0000[0-9A-F]{2}00$",
  hex: true,
  count: 8,
};

// Constructs Go's RE2 rejects but JavaScript accepts (so a JS compile check
// alone would let them through and Caddy would refuse the whole config).
const RE2_UNSUPPORTED = [
  { re: /\(\?<?[=!]/, what: "lookahead/lookbehind" },
  { re: /\\[1-9]/, what: "backreferences" },
  { re: /\\k</, what: "named backreferences" },
];

export function validateL4RegexpMatcher(pattern: string | undefined, config: Partial<L4RegexpMatcherConfig> | null | undefined) {
  if (!pattern || pattern.length === 0) {
    throw new Error("Regexp matcher requires a pattern");
  }
  if (pattern.length > L4_REGEXP_MAX_PATTERN_LENGTH) {
    throw new Error(`Regexp pattern must be at most ${L4_REGEXP_MAX_PATTERN_LENGTH} characters`);
  }
  for (const { re, what } of RE2_UNSUPPORTED) {
    if (re.test(pattern)) {
      throw new Error(`Regexp pattern uses ${what}, which Caddy's RE2 engine does not support`);
    }
  }
  try {
    new RegExp(pattern);
  } catch (error) {
    throw new Error(`Invalid regexp pattern: ${error instanceof Error ? error.message : String(error)}`);
  }

  const count = config?.count;
  if (count !== undefined && count !== null) {
    if (!Number.isInteger(count) || count < 1 || count > L4_REGEXP_MAX_COUNT) {
      throw new Error(`Bytes to inspect must be an integer between 1 and ${L4_REGEXP_MAX_COUNT}`);
    }
  }
}

export function normalizeL4RegexpMatcher(config: Partial<L4RegexpMatcherConfig> | null | undefined): L4RegexpMatcherConfig {
  return {
    hex: Boolean(config?.hex),
    count: config?.count ?? L4_REGEXP_DEFAULT_COUNT,
  };
}

/**
 * caddy-l4's regexp matcher runs the pattern through Caddy's replacer before
 * compiling it, so `{3}` / `{2,4}` quantifiers would be taken for placeholders
 * and silently replaced with "". Caddy's `\{` escape yields a literal `{`
 * (a user-written `\{` becomes `\\{`, which comes out as `\{` again).
 */
function escapeCaddyPlaceholders(pattern: string): string {
  return pattern.replace(/\{/g, "\\{");
}

/**
 * Build the caddy-l4 matcher set (one entry of route.match) for a host, or
 * null when the host matches every connection.
 */
export function buildL4MatcherSet(
  matcherType: string,
  matcherValues: string[],
  regexp: Partial<L4RegexpMatcherConfig> | null | undefined
): Record<string, unknown> | null {
  switch (matcherType) {
    case "tls_sni":
      return matcherValues.length > 0 ? { tls: { sni: matcherValues } } : null;
    case "http_host":
      return matcherValues.length > 0 ? { http: [{ host: matcherValues }] } : null;
    case "proxy_protocol":
      return { proxy_protocol: {} };
    case "ssh":
      return { ssh: {} };
    case "regexp": {
      const pattern = matcherValues[0];
      if (!pattern) return null;
      const { hex, count } = normalizeL4RegexpMatcher(regexp);
      return { regexp: { pattern: escapeCaddyPlaceholders(pattern), count, ...(hex ? { hex: true } : {}) } };
    }
    // Protocol-signature matchers with no parameters: each validates a
    // fixed-position protocol header/handshake byte-for-byte, so an empty
    // object is a complete, unambiguous matcher.
    case "rdp":
    case "socks4":
    case "socks5":
    case "wireguard":
    case "xmpp":
    case "postgres":
    case "winbox":
    case "openvpn":
      return { [matcherType]: {} };
    default:
      return null;
  }
}

/** Matcher types restricted to TCP because the underlying protocol/matcher only runs over TCP. */
export const L4_TCP_ONLY_MATCHER_TYPES = ["ssh", "rdp", "socks4", "socks5", "postgres", "winbox"] as const;
