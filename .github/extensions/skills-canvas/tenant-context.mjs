// Selection is UI state, not authentication. Every launch carries its own
// immutable routing envelope; result routing never consults the current picker.
// Registry parsing mirrors scripts/tenant_context.py (contract.mjs holds the
// shared primitives); tests/fixtures/tenant_contract/registry.json pins parity.
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import path from "node:path";
import { stateRoot } from "./paths.mjs";
import {
    CAPABILITIES, guid, optionalGuid, text, reference, mapping, isObject, normalizeCapabilities, huntWindow, isHuntChild,
    validHuntId, lookbackDays as checkedLookback, staticUnsupported, scopeFromContext,
} from "./contract.mjs";

const SLUG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const object = (v) => v && typeof v === "object" && !Array.isArray(v);
const scopes = new AsyncLocalStorage();
const PROFILE_FIELDS = new Set(["tenant_id", "subscription_id", "sentinel_workspace_id", "azure_mcp", "memory_file",
    "connections", "workspaces", "triage_home_tenant_id", "sit_mapping", "label_mapping", "sit_priority"]);
const AZURE_FIELDS = new Set(["tenant", "subscription", "resource_group", "workspace_name"]);
const WORKSPACE_FIELDS = new Set(["id", "name", "subscription_id", "resource_group"]);
const CONNECTION_KINDS = ["data_lake", "graph", "triage"];

export function safeSlug(value) {
    if (typeof value !== "string" || !SLUG.test(value) || ["__proto__", "constructor", "prototype"].includes(value)) {
        throw new Error("Invalid tenant profile slug");
    }
    return value;
}

// Single-tenant (no registry) configs were never validated this strictly; keep that.
function legacyMemoryFile(value) {
    if (!value) return "";
    if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) {
        throw new Error("memory_file must be an explicit basename");
    }
    return value;
}

function parseWorkspace(raw, key) {
    if (!object(raw)) throw new Error(`Invalid ${key} workspace`);
    if (Object.keys(raw).some((k) => !WORKSPACE_FIELDS.has(k))) throw new Error("Unknown workspace field");
    return {
        id: guid(raw.id, `${key}.workspace.id`),
        name: text(raw.name, `${key}.workspace.name`),
        subscription_id: optionalGuid(raw.subscription_id, `${key}.workspace.subscription_id`),
        resource_group: text(raw.resource_group, `${key}.workspace.resource_group`),
    };
}

// Unlisted metadata stays null (the UI falls back to the ID); only the profile's
// default workspace is enriched, and only from this same profile.
function parseProfile(key, raw) {
    safeSlug(key);
    if (!object(raw)) throw new Error(`Invalid tenant profile: ${key}`);
    if (Object.keys(raw).some((k) => !PROFILE_FIELDS.has(k))) {
        throw new Error(`Unknown profile field in ${key}; store connection names, not credentials`);
    }
    const tenantId = guid(raw.tenant_id, `${key}.tenant_id`);
    const declaredSubscription = optionalGuid(raw.subscription_id, `${key}.subscription_id`);
    const primary = optionalGuid(raw.sentinel_workspace_id, `${key}.sentinel_workspace_id`);
    const azure = raw.azure_mcp === undefined ? {} : raw.azure_mcp;
    if (!object(azure)) throw new Error(`Invalid ${key}.azure_mcp`);
    if (Object.keys(azure).some((k) => !AZURE_FIELDS.has(k))) throw new Error(`Unknown ${key}.azure_mcp field`);
    if (azure.tenant != null && guid(azure.tenant, "azure_mcp.tenant") !== tenantId) throw new Error("azure_mcp tenant conflicts with profile");
    const azureSubscription = optionalGuid(azure.subscription, "azure_mcp.subscription");
    if (declaredSubscription && azureSubscription && declaredSubscription !== azureSubscription) {
        throw new Error("azure_mcp subscription conflicts with profile");
    }
    const subscription = declaredSubscription || azureSubscription;
    const workspaceName = text(azure.workspace_name, "azure_mcp.workspace_name");
    const resourceGroup = text(azure.resource_group, "azure_mcp.resource_group");
    if (raw.workspaces !== undefined && !Array.isArray(raw.workspaces)) throw new Error(`Invalid ${key}.workspaces`);
    let workspaces = (raw.workspaces ?? []).map((item) => parseWorkspace(item, key));
    if (new Set(workspaces.map((w) => w.id)).size !== workspaces.length) throw new Error(`Duplicate ${key} workspace`);
    if (primary && !workspaces.some((w) => w.id === primary)) {
        workspaces.push({ id: primary, name: workspaceName, subscription_id: subscription, resource_group: resourceGroup });
    } else if (primary) {
        const listed = workspaces.find((w) => w.id === primary);
        for (const [field, value] of [["name", workspaceName], ["subscription_id", subscription], ["resource_group", resourceGroup]]) {
            if (value && listed[field] && value !== listed[field]) throw new Error("Default workspace metadata conflicts with azure_mcp");
        }
        workspaces = workspaces.map((w) => w.id !== primary ? w : {
            id: w.id, name: w.name || workspaceName, subscription_id: w.subscription_id || subscription,
            resource_group: w.resource_group || resourceGroup,
        });
    }
    if (raw.connections !== undefined && !object(raw.connections)) throw new Error(`Invalid ${key}.connections`);
    if (Object.keys(raw.connections || {}).some((k) => !CONNECTION_KINDS.includes(k))) throw new Error("Unknown connection type");
    const connections = {};
    for (const kind of CONNECTION_KINDS) {
        const name = raw.connections?.[kind];
        if (name != null) connections[kind] = reference(name, `${key}.connections.${kind}`);
    }
    const azureMcp = {};
    if (azure.tenant != null) azureMcp.tenant = tenantId;
    if (azureSubscription) azureMcp.subscription = azureSubscription;
    if (resourceGroup) azureMcp.resource_group = resourceGroup;
    if (workspaceName) azureMcp.workspace_name = workspaceName;
    return {
        key, tenantId, subscriptionId: subscription || "", sentinelWorkspaceId: primary || "", connections, workspaces,
        memoryFile: raw.memory_file == null ? "" : reference(text(raw.memory_file, "memory_file"), "memory_file"),
        azureMcp, triageHomeTenantId: optionalGuid(raw.triage_home_tenant_id, "triage_home_tenant_id") || "",
        // Tenant-local GUID tables for the CLI; stripped from UI and prompt payloads.
        mappings: {
            sit: mapping(raw.sit_mapping, "sit_mapping"), label: mapping(raw.label_mapping, "label_mapping"),
            priority: mapping(raw.sit_priority, "sit_priority", { tiers: true }),
        },
    };
}

export function parseRegistry(config) {
    if (!object(config)) throw new Error("Invalid config.json");
    if (!own(config, "tenants")) return { registered: false, profiles: [] };
    if (!isObject(config.tenants)) throw new Error("tenants must be an object of tenant profiles");
    const entries = Object.entries(config.tenants);
    if (!entries.length) return { registered: false, profiles: [] };
    return { registered: true, profiles: entries.map(([key, raw]) => parseProfile(key, raw)) };
}

// Mapping tables are CLI inputs, not UI state or prompt content.
export function publicProfile(profile) {
    const { mappings, ...rest } = profile;
    return rest;
}

export async function readRegistry(repoRoot) {
    let source;
    try { source = await readFile(path.join(repoRoot, "config.json"), "utf8"); }
    catch (err) {
        if (err.code === "ENOENT") return { registered: false, profiles: [] };
        throw err;
    }
    return parseRegistry(JSON.parse(source));
}

export async function legacyContext(repoRoot) {
    let c;
    try { c = JSON.parse(await readFile(path.join(repoRoot, "config.json"), "utf8")); }
    catch { return null; }
    if (!GUID.test(c.tenant_id || "")) return null;
    const workspaceId = GUID.test(c.sentinel_workspace_id || "") ? c.sentinel_workspace_id.toLowerCase() : "";
    return freeze({
        legacy: true, key: "legacy", tenantId: c.tenant_id.toLowerCase(),
        subscriptionId: GUID.test(c.subscription_id || "") ? c.subscription_id.toLowerCase() : "",
        workspace: workspaceId ? { id: workspaceId, name: c.azure_mcp?.workspace_name || workspaceId,
            subscription_id: c.subscription_id || "", resource_group: c.azure_mcp?.resource_group || "" } : null,
        connections: structuredClone(c.connections || {}), azureMcp: structuredClone(c.azure_mcp || {}),
        memoryFile: legacyMemoryFile(c.memory_file), triageHomeTenantId: c.triage_home_tenant_id || "",
        caseId: `case-${randomUUID()}`, defenderOnly: false, huntId: null, lookbackDays: null, window: null, capabilities: [],
    });
}

// `extra` pins hunt/case parameters (all optional):
//   huntId + lookbackDays + windowEnd  one shared window for a hunt child (caseId must be <huntId>-NN)
//   capabilities                       extra required capabilities (tenant_identity is always required)
//   defenderOnly                       bind no Sentinel workspace, even if the profile lists some
// Capabilities this scope can never provide are NOT rejected here: callers use
// blockedByStaticLimits() so such a target is reported unavailable, never dropped.
export function selectContext(registry, key, workspaceId, caseId = "", extra = {}) {
    if (!registry.registered) return null;
    safeSlug(key);
    const profile = registry.profiles.find((p) => p.key === key);
    if (!profile) throw new Error("Unknown tenant profile");
    const defenderOnly = extra.defenderOnly === true;
    if (defenderOnly && workspaceId) throw new Error("A Defender-only context cannot name a workspace");
    const id = workspaceId ? guid(workspaceId, "workspace ID") : "";
    if (profile.workspaces.length > 1 && !id && !defenderOnly) throw new Error("Explicit workspace selection required");
    const workspace = defenderOnly ? null : id ? profile.workspaces.find((w) => w.id === id) : profile.workspaces[0] || null;
    if (id && !workspace) throw new Error("Workspace does not belong to selected profile");
    if (caseId && !SLUG.test(caseId)) throw new Error("Case must be a lowercase safe slug (1–64 characters)");
    const huntId = extra.huntId == null ? null : validHuntId(extra.huntId);
    if (huntId && !isHuntChild(huntId, caseId)) throw new Error("A hunt case ID must be <hunt-id>-NN with NN from 01 to 99");
    if (huntId && !extra.windowEnd) throw new Error("A hunt context requires one pinned window end shared by every target");
    const pinned = huntId ? huntWindow(extra.lookbackDays, extra.windowEnd, extra.nowMs ?? Date.now()) : null;
    const lookbackDays = pinned ? pinned.lookback_days : extra.lookbackDays == null ? null : checkedLookback(extra.lookbackDays);
    return freeze({
        ...structuredClone(publicProfile(profile)), workspace: workspace ? { ...workspace } : null,
        caseId: caseId || `case-${randomUUID()}`, defenderOnly, huntId, lookbackDays,
        // Same two keys the CLI writes to context.json.
        window: pinned ? { start_utc: pinned.start_utc, end_utc: pinned.end_utc } : null,
        capabilities: normalizeCapabilities(extra.capabilities ?? null, workspace !== null),
    });
}

function freeze(value) {
    if (object(value) || Array.isArray(value)) {
        for (const v of Object.values(value)) freeze(v);
        Object.freeze(value);
    }
    return value;
}

export function stateScope(repoRoot, context) {
    if (!context || context.legacy) return repoRoot;
    safeSlug(context.key);
    const id = guid(context.tenantId, "tenant ID");
    // Reusing a slug for a different customer must never expose the old board.
    const fingerprint = createHash("sha256").update(id).digest("hex").slice(0, 16);
    return Object.freeze({ repoRoot, tenantKey: context.key, tenantFingerprint: fingerprint });
}

export function inTenant(context, fn) { return scopes.run(context, fn); }
export function currentTenant() { return scopes.getStore(); }

export class LaunchBindings {
    #bindings = new Map();
    capture(context, skill, sessionId) {
        const binding = freeze({
            correlationId: randomUUID(), context: context ? structuredClone(context) : null,
            skill, sessionId, createdAt: Date.now(),
        });
        this.#bindings.set(binding.correlationId, binding);
        return binding;
    }
    require(input, sessionId) {
        const b = this.#bindings.get(input?.correlationId);
        if (!b || b.sessionId !== sessionId) throw new Error("Unknown launch correlation; results were not recorded");
        if (Date.now() - b.createdAt > 24 * 60 * 60 * 1000) throw new Error("Launch correlation expired");
        if (input.profile !== (b.context?.key || "legacy") ||
            input.tenantId !== (b.context?.tenantId || "") ||
            input.workspaceId !== (b.context?.workspace?.id || "") ||
            input.caseId !== (b.context?.caseId || "")) {
            throw new Error("Finding context does not match the captured launch");
        }
        return b;
    }
}

export function bindingFields(binding) {
    const c = binding.context;
    return {
        correlationId: binding.correlationId, profile: c?.key || "legacy",
        tenantId: c?.tenantId || "", workspaceId: c?.workspace?.id || "", caseId: c?.caseId || "",
    };
}

const contextPath = (c) => `reports/tenants/${c.key}/${c.caseId}/context.json`;

// What the CLI can enforce for this context: the requested capabilities minus
// those declared configuration can never provide (`create` rejects those).
const enforceable = (c, unsupported) => c.capabilities.filter((name) => !Object.hasOwn(unsupported, name));

// Required capabilities split into what a launch can enforce and what the
// declared configuration rules out, with the reason, so a target is reported
// as unavailable rather than silently shrunk or dropped.
export function staticCoverage(context) {
    const reasons = context.legacy ? {} : staticUnsupported(scopeFromContext(context));
    return {
        required: enforceable(context, reasons),
        unsupported: context.capabilities.filter((name) => Object.hasOwn(reasons, name))
            .map((capability) => ({ capability, reason: reasons[capability] })),
    };
}

// Every value below is already validated (slug, GUID, UTC stamp, fixed capability
// names), so the frozen command can be handed to the agent verbatim.
function createCommand(c, unsupported) {
    const parts = ["python scripts/tenant_context.py create", `--profile ${c.key}`,
        c.workspace ? `--workspace ${c.workspace.id}` : "--no-workspace", `--case ${c.caseId}`,
        `--lookback-days ${c.lookbackDays ?? "<requested-days>"}`];
    if (c.huntId) parts.push(`--hunt-id ${c.huntId}`, `--window-end ${c.window.end_utc}`);
    // Explicit --capability flags replace the CLI default, so name every one.
    for (const name of enforceable(c, unsupported)) parts.push(`--capability ${name}`);
    parts.push("--validate-live");
    return parts.join(" ");
}

function registryInstructions(c, unsupported) {
    const ctx = contextPath(c);
    const attestable = Object.entries(CAPABILITIES).filter(([, spec]) => spec.proof === "attested").map(([name]) => name);
    return [
        "Use only this profile, workspace, case and named connections. Never fall back to top-level config, another profile, mutable UI selection, shared memory or another workspace.",
        "Before any data access run these commands in order. If this case's context.json already exists (a follow-up in the same case), skip step 1 and never recreate or overwrite it. " +
            "They are read-only against the tenant and write only local case artifacts below the case directory:",
        `1. ${createCommand(c, unsupported)}`,
        `2. python scripts/tenant_context.py verify ${ctx}`,
        `3. For each MCP capability you intend to use (${attestable.join(", ")}), verify that connection's authenticated tenant yourself, then record your claim: ` +
            `python scripts/tenant_context.py attest ${ctx} --capability <name> --status <attested|denied|unverified> --detail "<non-secret evidence>" ` +
            "(defender_hunting also needs --via <triage|graph|portal>). An attestation is your claim, not proof: MCP auth remains unverified by the CLI. " +
            "A connection name, server/header label, Azure CLI login, B2B guest sign-in or tenant header does NOT prove which tenant an MCP session is authenticated to, and grants no roles.",
        `4. python scripts/tenant_context.py readiness ${ctx} — query only capabilities listed under "usable". ` +
            "Report blocked, denied, expired, unverified or unsupported capabilities as unavailable, never as clean.",
        Object.keys(unsupported).length
            ? `Statically unsupported for this target (declared configuration, do not attempt): ${Object.keys(unsupported).join(", ")}.` : "",
        c.window
            ? `COLLECTION WINDOW (UTC, identical for every target of hunt ${c.huntId}): ${c.window.start_utc} .. ${c.window.end_utc}. ` +
              "Filter time with between (datetime(<start>) .. datetime(<end>)) — never ago() or any relative window."
            : "",
    ].filter(Boolean);
}

// `handoff` renders the same frozen context for a separate chat/client session
// that Mission Control does not own: no correlation token, no canvas actions.
export function launchEnvelope(binding, { handoff = false } = {}) {
    const c = binding.context;
    const registry = c && !c.legacy;
    const unsupported = registry ? staticUnsupported(scopeFromContext(c)) : {};
    const fields = bindingFields(binding);
    if (handoff) delete fields.correlationId;
    return [
        handoff ? "MISSION CONTROL — DETACHED HAND-OFF CONTEXT (not proof of authentication)"
            : "MISSION CONTROL — FROZEN LAUNCH CONTEXT (not proof of authentication)",
        JSON.stringify({ ...fields, subscriptionId: c?.subscriptionId || "",
            workspace: c?.workspace || null, connections: c?.connections || {}, azure_mcp: c?.azureMcp || {},
            triage_home_tenant_id: c?.triageHomeTenantId || "", memory_file: c?.memoryFile || "",
            hunt_id: c?.huntId ?? null, lookback_days: c?.lookbackDays ?? null, window: c?.window ?? null,
            required_capabilities: c ? enforceable(c, unsupported) : [], unsupported_capabilities: unsupported }),
        ...(registry ? registryInstructions(c, unsupported)
            : ["Legacy single-tenant mode: validate the configured tenant and authenticated data connections before access."]),
        !registry || c.workspace
            ? "Enumerate available Sentinel workspaces using the selected connection and verify the captured workspace ID belongs to this tenant. If a workspace is not captured, stop for explicit selection when multiple exist. Never auto-select all, switch on failure, or interpret access failures as clean results."
            : "No Sentinel workspace is bound to this case (Defender-only). Do not enumerate or query Sentinel workspaces; use only Defender/Entra capabilities that readiness reports usable.",
        c?.triageHomeTenantId && c.triageHomeTenantId !== c.tenantId
            ? "TRIAGE UNAVAILABLE: Triage is home-tenant-bound and its home tenant differs from this profile. Do not query Triage for this target."
            : "Triage can be used only after its authenticated/home tenant is verified to equal this target; otherwise report it unavailable.",
        c?.memoryFile ? `Consult ONLY tenant memory '${c.memoryFile}' under ~/.copilot/memories/repo/. If absent, report unavailable; no cross-tenant fallback.`
            : "No explicit profile memory configured. Do not consult a generic or another tenant's memory.",
        registry ? `Write reports only below reports/tenants/${c.key}/${c.caseId}/; do not browse other tenants' reports.` : "",
        ...(handoff
            ? ["DETACHED HAND-OFF: this session has no Mission Control launch binding. Do not call record_finding or record_hunt_status; " +
               "keep every artifact under the case directory and state this target's usable, blocked and unsupported capabilities in its report."]
            : ["When recording this result, invoke_canvas_action record_finding with ALL these exact correlation fields:",
               JSON.stringify(bindingFields(binding))]),
        "Report query/auth/capability failures as errors or unknown, never severity clean.",
        binding.skill === "cross-tenant-hunt" ? "READ-ONLY HUNT: Do not change tenant/resource state."
            : "Follow the skill's authorization/remediation rules; preserve this exact tenant/case binding for any explicitly authorized action.",
    ].filter(Boolean).join("\n");
}

const statusWrites = new Map();
export async function huntStatuses(repoRoot, context) {
    try {
        const rows = JSON.parse(await readFile(path.join(stateRoot(stateScope(repoRoot, context)), "hunts.json"), "utf8"));
        return Array.isArray(rows) ? rows : [];
    } catch { return []; }
}

export async function updateHuntStatus(repoRoot, binding, status, detail = "", findingId = "") {
    if (!["pending", "running", "complete", "error", "unavailable"].includes(status)) throw new Error("Invalid hunt status");
    const root = stateRoot(stateScope(repoRoot, binding.context));
    const previous = statusWrites.get(root) || Promise.resolve();
    const write = previous.catch(() => {}).then(async () => {
        const rows = await huntStatuses(repoRoot, binding.context);
        const row = { ...bindingFields(binding), huntId: binding.context?.huntId ?? null, skill: binding.skill, status,
            detail: String(detail).slice(0, 1000), findingId, updatedAt: Date.now() };
        const next = [row, ...rows.filter((r) => r.correlationId !== row.correlationId)].slice(0, 100);
        await mkdir(root, { recursive: true });
        await writeFile(path.join(root, "hunts.json"), JSON.stringify(next, null, 2), "utf8");
        return row;
    });
    statusWrites.set(root, write);
    try { return await write; }
    finally { if (statusWrites.get(root) === write) statusWrites.delete(root); }
}
