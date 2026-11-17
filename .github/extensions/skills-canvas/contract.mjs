// Pure mirror of the tenant-context contract in scripts/tenant_context.py.
//
// Python is authoritative: it creates contexts, probes tenants and writes the
// capability ledger. This module only re-validates what Python wrote and
// recomputes the same readiness, so Mission Control never trusts a record the
// CLI would reject. There is no filesystem, process or clock access here;
// callers pass the current time as epoch milliseconds (`nowMs`).
//
// Parity is pinned by tests/fixtures/tenant_contract/*.json, which both test
// suites consume. Known benign divergences: JSON `1.0` is indistinguishable
// from `1` once parsed in JavaScript, and Unicode case folding of the secret
// guard can differ for exotic letters (Python decides at write time).

export class ContractError extends Error {}

const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
export const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
export const codePoints = (value) => Array.from(value).length;

// Python's str.isspace()/split() whitespace. JavaScript's trim() differs
// (it strips U+FEFF but not U+001C-U+001F or U+0085), so spell it out.
const WS = "\\t\\n\\v\\f\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const WS_RUN = new RegExp(`[${WS}]+`, "u");
const WS_ONLY = new RegExp(`^[${WS}]*$`, "u");
export const isBlank = (value) => WS_ONLY.test(value);

const SECRET_LIKE = new RegExp(
    `eyJ[A-Za-z0-9_-]{8,}|bearer[${WS}]+[^${WS}]{12,}|(?:secret|password|token|apikey|api_key)[${WS}]*[=:][${WS}]*[^${WS}]`, "iu");

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NIL_GUID = /^0{8}-0{4}-0{4}-0{4}-0{12}$/;
const SLUG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const HUNT_ID = /^[a-z0-9][a-z0-9_-]{0,59}$/;
const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const UTC = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
const STAMP = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})(\d{6})Z$/;
export const LEDGER_NAME = /^(\d{8}T\d{12}Z)-([a-z_]+)\.json$/;

export const CAPABILITIES = Object.freeze({
    tenant_identity: Object.freeze({ proof: "cli", scoped: false }),
    workspace_arm: Object.freeze({ proof: "cli", scoped: true }),
    workspace_query: Object.freeze({ proof: "cli", scoped: true }),
    data_lake: Object.freeze({ proof: "attested", scoped: true }),
    graph: Object.freeze({ proof: "attested", scoped: false }),
    triage: Object.freeze({ proof: "attested", scoped: false }),
    defender_hunting: Object.freeze({ proof: "attested", scoped: false }),
});
const CONNECTION_FOR = Object.freeze(["data_lake", "graph", "triage"]);
export const HUNTING_VIA = Object.freeze(["triage", "graph", "portal"]);
export const USABLE = Object.freeze(["verified", "attested"]);
const LEDGER_STATUSES = Object.freeze({
    cli_probe: Object.freeze(["verified", "denied", "unverified"]),
    agent_attestation: Object.freeze(["attested", "denied", "unverified"]),
});
const LEDGER_FIELDS = Object.freeze([
    "schema_version", "kind", "profile", "tenant_id", "workspace_id", "case_id",
    "capability", "status", "method", "checked_at", "expires_at", "detail", "via",
]);
export const MAX_TTL_HOURS = 168;
export const MAX_RECORD_BYTES = 8192;
export const CLOCK_SKEW_MS = 5 * 60 * 1000;
const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
// 0001-01-01T00:00:00Z, the earliest instant Python's datetime can represent.
const MIN_MS = -62_135_596_800_000;

// ── Primitives (the registry parser reuses these) ────────────────────────────

export function guid(value, field) {
    if (typeof value !== "string" || !GUID.test(value) || NIL_GUID.test(value)) {
        throw new ContractError(`${field} must be a nonzero canonical GUID`);
    }
    return value.toLowerCase();
}

export const optionalGuid = (value, field) => (value == null ? null : guid(value, field));

export function text(value, field) {
    if (value == null) return null;
    if (typeof value !== "string" || isBlank(value) || codePoints(value) > 256) {
        throw new ContractError(`${field} must be a nonempty string`);
    }
    if (/[\u0000-\u001f/\\]/.test(value)) throw new ContractError(`${field} must be a name, not a path`);
    return value;
}

export function reference(value, field) {
    if (typeof value !== "string" || !REFERENCE.test(value)) throw new ContractError(`${field} must be a name`);
    return value;
}

export function slug(value, field) {
    if (typeof value !== "string" || !SLUG.test(value)) {
        throw new ContractError(`${field} must be a safe lowercase slug (1-64 characters)`);
    }
    return value;
}

const TIERS = Object.freeze({ high: "High", medium: "Medium", low: "Low" });

// Tenant-local GUID tables, normalized exactly like the CLI: lowercase GUID
// keys, short single-line values (or High/Medium/Low), sorted, no duplicates.
export function mapping(raw, field, { tiers = false } = {}) {
    if (raw == null) return [];
    if (!isObject(raw)) throw new ContractError(`${field} must be an object`);
    const entries = new Map();
    for (const [key, value] of Object.entries(raw)) {
        if (key === "__comment") continue;
        const id = guid(key.toLowerCase(), `${field} key`);
        let label;
        if (tiers) {
            label = typeof value === "string" && own(TIERS, value.toLowerCase()) ? TIERS[value.toLowerCase()] : undefined;
            if (label === undefined) throw new ContractError(`${field} values must be High, Medium, or Low`);
        } else if (typeof value !== "string" || isBlank(value) || codePoints(value) > 160 || /[\u0000-\u001f]/.test(value)) {
            throw new ContractError(`${field} values must be short single-line names`);
        } else {
            label = value;
        }
        if (entries.has(id)) throw new ContractError(`${field} contains duplicate GUIDs`);
        entries.set(id, label);
    }
    return [...entries].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
}

// Strict `YYYY-MM-DDTHH:MM:SSZ` → epoch ms. Rejects impossible calendar dates
// (Feb 30), 24:00, leap seconds, and years before 0001.
export function parseUtc(value, field = "timestamp") {
    const match = typeof value === "string" ? UTC.exec(value) : null;
    const invalid = () => new ContractError(`${field} must be UTC time formatted YYYY-MM-DDTHH:MM:SSZ`);
    if (!match) throw invalid();
    const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
    if (year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) throw invalid();
    const moment = new Date(0);
    moment.setUTCFullYear(year, month - 1, day);
    moment.setUTCHours(hour, minute, second, 0);
    if (moment.getUTCFullYear() !== year || moment.getUTCMonth() !== month - 1 || moment.getUTCDate() !== day) throw invalid();
    return moment.getTime();
}

export const formatUtc = (ms) => new Date(ms).toISOString().slice(0, 19) + "Z";

// ── Hunts: one shared window, numbered child cases ───────────────────────────

export function lookbackDays(value) {
    if (!Number.isInteger(value) || value < 1 || value > 3650) {
        throw new ContractError("lookback_days must be an integer between 1 and 3650");
    }
    return value;
}

export function validHuntId(value) {
    if (typeof value !== "string" || !HUNT_ID.test(value)) {
        throw new ContractError("hunt_id must be a safe lowercase slug (1-60 characters)");
    }
    return value;
}

export function huntChildId(huntId, index) {
    validHuntId(huntId);
    if (!Number.isInteger(index) || index < 1 || index > 99) throw new ContractError("A hunt has 1 to 99 child cases");
    return `${huntId}-${String(index).padStart(2, "0")}`;
}

export function isHuntChild(huntId, caseId) {
    return typeof huntId === "string" && typeof caseId === "string" && caseId.startsWith(`${huntId}-`) &&
        /^(?:0[1-9]|[1-9]\d)$/.test(caseId.slice(huntId.length + 1));
}

// The exact collection window shared by every child of a hunt. `windowEnd`
// pins the end (UTC seconds); by default it is "now" floored to the second.
export function huntWindow(days, windowEnd = null, nowMs = Date.now()) {
    lookbackDays(days);
    const end = windowEnd == null ? Math.floor(nowMs / 1000) * 1000 : parseUtc(windowEnd, "window_end");
    if (end > nowMs + CLOCK_SKEW_MS) throw new ContractError("window_end cannot be in the future");
    const start = end - days * DAY_MS;
    if (start < MIN_MS) throw new ContractError("window_end is too early for the requested lookback");
    return { lookback_days: days, start_utc: formatUtc(start), end_utc: formatUtc(end) };
}

// ── Scope: the part of a context the ledger rules need ───────────────────────

const connectionsOf = (value) => Object.freeze({
    data_lake: value?.data_lake ?? null, graph: value?.graph ?? null, triage: value?.triage ?? null,
});

// From a Mission Control context (camelCase, see tenant-context.mjs).
export function scopeFromContext(context) {
    return Object.freeze({
        profile: context.key, tenantId: context.tenantId, caseId: context.caseId,
        workspaceId: context.workspace?.id ?? null, connections: connectionsOf(context.connections),
        triageHomeTenantId: context.triageHomeTenantId || null,
        capabilities: Object.freeze([...(context.capabilities ?? [])]),
        huntId: context.huntId ?? null, window: context.window ? Object.freeze({ ...context.window }) : null,
    });
}

// From a context.json manifest written by scripts/tenant_context.py (snake_case).
export function scopeFromManifest(raw) {
    return Object.freeze({
        profile: raw.profile, tenantId: raw.tenant_id, caseId: raw.case_id,
        workspaceId: raw.workspace?.id ?? null, connections: connectionsOf(raw.connections),
        triageHomeTenantId: raw.triage_home_tenant_id ?? null,
        capabilities: Object.freeze([...(raw.capabilities ?? [])]),
        huntId: raw.hunt_id ?? null, window: raw.window ? Object.freeze({ ...raw.window }) : null,
    });
}

// Capabilities this scope can never provide, from declared configuration only.
export function staticUnsupported(scope) {
    const reasons = {};
    const home = scope.triageHomeTenantId;
    if (home != null && home !== scope.tenantId) {
        reasons.triage = "Triage is home-tenant only; declared home tenant differs from this tenant";
    }
    if (!scope.workspaceId) {
        for (const [name, spec] of Object.entries(CAPABILITIES)) {
            if (spec.scoped) reasons[name] = "No workspace is bound to this case";
        }
    }
    return reasons;
}

// Required capabilities of a new case: tenant identity is always required.
export function normalizeCapabilities(requested, hasWorkspace) {
    if (requested != null && !Array.isArray(requested)) throw new ContractError("capabilities must be an array");
    const names = requested == null
        ? ["tenant_identity", ...(hasWorkspace ? ["workspace_arm"] : [])]
        : ["tenant_identity", ...requested];
    if (names.some((name) => typeof name !== "string" || !own(CAPABILITIES, name))) {
        throw new ContractError("Unknown capability; expected: " + Object.keys(CAPABILITIES).sort().join(", "));
    }
    const unique = [...new Set(names)].sort();
    const scoped = unique.filter((name) => CAPABILITIES[name].scoped);
    if (!hasWorkspace && scoped.length) throw new ContractError("Capabilities require a workspace: " + scoped.join(", "));
    return unique;
}

// Required capabilities this scope can never satisfy.
export function blockedByStaticLimits(scope) {
    const reasons = staticUnsupported(scope);
    return scope.capabilities.filter((name) => own(reasons, name)).map((name) => ({ capability: name, reason: reasons[name] }));
}

// ── Ledger records ───────────────────────────────────────────────────────────

export function cleanDetail(value) {
    if (typeof value !== "string") throw new ContractError("detail must be text");
    const detail = value.split(WS_RUN).filter(Boolean).join(" ");
    if (!detail || codePoints(detail) > 200 || /[\u0000-\u001f]/.test(detail)) {
        throw new ContractError("detail must be 1-200 characters of plain text");
    }
    if (SECRET_LIKE.test(detail)) throw new ContractError("detail must not contain tokens or credentials");
    return detail;
}

// `<YYYYMMDD>T<HHMMSS><6-digit micros>Z-<capability>.json`. Microseconds exceed
// 2^53 as milliseconds-times-1000 near year 9999, so they are BigInt.
export function parseLedgerFileName(name) {
    const match = typeof name === "string" ? LEDGER_NAME.exec(name) : null;
    if (!match) throw new ContractError("Not a ledger file name");
    const [, year, month, day, hour, minute, second, micros] = STAMP.exec(match[1]);
    const seconds = parseUtc(`${year}-${month}-${day}T${hour}:${minute}:${second}Z`, "ledger file stamp");
    return { capability: match[2], micros: BigInt(seconds) * 1000n + BigInt(micros) };
}

// Strictly validate one parsed ledger record for exactly this tenant/profile/case.
// Throws ContractError; returns the record with a normalized `detail`.
export function validateRecord(raw, scope, nowMs, fileName = null) {
    const reject = (message) => { throw new ContractError(message); };
    if (!isObject(raw)) reject("ledger record must be an object");
    const keys = Object.keys(raw);
    if (keys.length !== LEDGER_FIELDS.length || !keys.every((key) => LEDGER_FIELDS.includes(key))) {
        reject("Ledger record fields do not match the schema");
    }
    if (!Number.isInteger(raw.schema_version) || raw.schema_version !== 1 || raw.kind !== "capability_check") {
        reject("Unsupported ledger record");
    }
    if (raw.profile !== scope.profile || raw.tenant_id !== scope.tenantId || raw.case_id !== scope.caseId) {
        reject("Ledger record belongs to a different tenant, profile, or case");
    }
    const capability = raw.capability;
    if (typeof capability !== "string" || !own(CAPABILITIES, capability)) reject("Unknown capability");
    const { proof, scoped } = CAPABILITIES[capability];
    if (raw.workspace_id !== (scoped ? scope.workspaceId : null)) reject("Ledger record belongs to a different workspace");
    const { method, status } = raw;
    if (typeof method !== "string" || typeof status !== "string" || !own(LEDGER_STATUSES, method) ||
        !LEDGER_STATUSES[method].includes(status)) reject("Invalid ledger method or status");
    if ((proof === "cli") !== (method === "cli_probe")) reject("Ledger method does not match how this capability is proven");
    const checked = parseUtc(raw.checked_at, "checked_at");
    const expires = parseUtc(raw.expires_at, "expires_at");
    if (!(checked < expires && expires <= checked + MAX_TTL_HOURS * HOUR_MS)) reject("Ledger expiry is outside the allowed lifetime");
    if (checked > nowMs + CLOCK_SKEW_MS) reject("Ledger record is dated in the future");
    if (fileName !== null) {
        const named = parseLedgerFileName(fileName);
        const age = named.micros - BigInt(checked) * 1000n;
        if (named.capability !== capability || age < 0n || age >= 2_000_000n) reject("Ledger file name does not match its record");
    }
    const via = raw.via;
    if (capability === "defender_hunting") {
        if (via !== null && !HUNTING_VIA.includes(via)) reject("via must be triage, graph, or portal");
        if (status === "attested" && via === null) reject("A defender_hunting attestation must name its route");
    } else if (via !== null) {
        reject("via applies only to defender_hunting");
    }
    if (status === "attested") {
        const needed = CONNECTION_FOR.includes(capability) ? [capability] : [];
        if (via === "triage" || via === "graph") needed.push(via);
        for (const name of needed) {
            if (scope.connections[name] == null) reject(`No ${name} connection is declared for this tenant`);
        }
        if ((capability === "triage" || via === "triage") && own(staticUnsupported(scope), "triage")) {
            reject("Triage is not supported for this tenant");
        }
    }
    return { ...raw, detail: cleanDetail(raw.detail) };
}

// ── Readiness ────────────────────────────────────────────────────────────────

// `records` maps capability → the newest valid record (as read from the ledger).
export function evaluateCapabilities(scope, records, nowMs) {
    const unsupported = staticUnsupported(scope);
    const table = {};
    for (const [name, spec] of Object.entries(CAPABILITIES)) {
        const entry = {
            status: "unverified", proof: spec.proof, required: scope.capabilities.includes(name),
            method: null, checked_at: null, expires_at: null, detail: null, via: null, last_status: null,
        };
        const record = own(records, name) ? records[name] : null;
        if (own(unsupported, name)) {
            entry.status = "unsupported";
            entry.detail = unsupported[name];
        } else if (record) {
            const expired = nowMs >= parseUtc(record.expires_at, "expires_at");
            Object.assign(entry, {
                status: expired ? "expired" : record.status, method: record.method,
                checked_at: record.checked_at, expires_at: record.expires_at, detail: record.detail,
                via: record.via, last_status: expired ? record.status : null,
            });
        } else {
            entry.detail = CONNECTION_FOR.includes(name) && scope.connections[name] == null
                ? "No connection is declared for this tenant" : "No check recorded";
        }
        table[name] = entry;
    }
    return table;
}

export function readinessFromRecords(scope, records, ignored, nowMs) {
    const capabilities = evaluateCapabilities(scope, records, nowMs);
    const blocked = scope.capabilities.filter((name) => !USABLE.includes(capabilities[name].status));
    return {
        ok: blocked.length === 0, profile: scope.profile, tenant_id: scope.tenantId,
        workspace_id: scope.workspaceId, case_id: scope.caseId, hunt_id: scope.huntId,
        window: scope.window ? { ...scope.window } : null, required: [...scope.capabilities], capabilities,
        usable: Object.entries(capabilities).filter(([, entry]) => USABLE.includes(entry.status)).map(([name]) => name),
        blocked, ignored_records: ignored,
    };
}
