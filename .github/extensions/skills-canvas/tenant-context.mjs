// Selection is UI state, not authentication. Every launch carries its own
// immutable routing envelope; result routing never consults the current picker.
import { readFile, mkdir, writeFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { AsyncLocalStorage } from "node:async_hooks";
import path from "node:path";
import { stateRoot } from "./paths.mjs";

const SLUG = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const object = (v) => v && typeof v === "object" && !Array.isArray(v);
const scopes = new AsyncLocalStorage();

export function safeSlug(value) {
    if (typeof value !== "string" || !SLUG.test(value) || ["__proto__", "constructor", "prototype"].includes(value)) {
        throw new Error("Invalid tenant profile slug");
    }
    return value;
}

function guid(value, field, optional = false) {
    if (optional && value == null) return "";
    if (typeof value !== "string" || !GUID.test(value) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(value)) throw new Error(`Invalid ${field}`);
    return value.toLowerCase();
}

function memoryFile(value) {
    if (!value) return "";
    if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) {
        throw new Error("memory_file must be an explicit basename");
    }
    return value;
}

export function parseRegistry(config) {
    if (!object(config)) throw new Error("Invalid config.json");
    if (!own(config, "tenants") || (object(config.tenants) && !Object.keys(config.tenants).length)) return { registered: false, profiles: [] };
    if (!object(config.tenants) || !Object.keys(config.tenants).length) throw new Error("tenants must be a non-empty profile object");
    const profiles = Object.entries(config.tenants).map(([key, p]) => {
        safeSlug(key);
        if (!object(p)) throw new Error(`Invalid tenant profile: ${key}`);
        const allowed = new Set(["tenant_id", "subscription_id", "sentinel_workspace_id", "azure_mcp",
            "memory_file", "connections", "workspaces", "triage_home_tenant_id"]);
        if (Object.keys(p).some(k => !allowed.has(k))) throw new Error(`Unknown profile field in ${key}; store connection names, not credentials`);
        const tenantId = guid(p.tenant_id, `${key}.tenant_id`);
        if (p.azure_mcp !== undefined && !object(p.azure_mcp)) throw new Error(`Invalid ${key}.azure_mcp`);
        const azure = p.azure_mcp || {};
        if (Object.keys(azure).some(k => !["tenant", "subscription", "resource_group", "workspace_name"].includes(k))) {
            throw new Error(`Unknown ${key}.azure_mcp field`);
        }
        if (azure.tenant != null && guid(azure.tenant, "azure_mcp.tenant") !== tenantId) throw new Error("azure_mcp tenant conflicts with profile");
        const azureSubscription = guid(azure.subscription, "azure_mcp.subscription", true);
        const declaredSubscription = guid(p.subscription_id, `${key}.subscription_id`, true);
        if (azureSubscription && declaredSubscription && azureSubscription !== declaredSubscription) throw new Error("azure_mcp subscription conflicts with profile");
        const subscriptionId = declaredSubscription || azureSubscription;
        if (p.connections !== undefined && !object(p.connections)) throw new Error(`Invalid ${key}.connections`);
        if (Object.keys(p.connections || {}).some(k => !["data_lake", "graph", "triage"].includes(k))) throw new Error("Unknown connection type");
        const connections = {};
        for (const kind of ["data_lake", "graph", "triage"]) {
            const name = p.connections?.[kind];
            if (name == null) continue;
            if (typeof name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(name)) {
                throw new Error(`Invalid ${key}.connections.${kind}`);
            }
            connections[kind] = name;
        }
        if (p.workspaces !== undefined && !Array.isArray(p.workspaces)) throw new Error(`Invalid ${key}.workspaces`);
        const workspaces = (p.workspaces || []).map((w) => {
            if (!object(w)) throw new Error(`Invalid ${key} workspace`);
            if (Object.keys(w).some(k => !["id", "name", "subscription_id", "resource_group"].includes(k))) throw new Error("Unknown workspace field");
            return {
                id: guid(w.id, `${key}.workspace.id`),
                name: String(w.name || w.id).slice(0, 160),
                subscription_id: guid(w.subscription_id ?? (subscriptionId || undefined), `${key}.workspace.subscription_id`, true),
                resource_group: String(w.resource_group || "").slice(0, 160),
            };
        });
        const primary = guid(p.sentinel_workspace_id, `${key}.sentinel_workspace_id`, true);
        if (primary && !workspaces.some((w) => w.id === primary)) {
            workspaces.push({ id: primary, name: String(azure.workspace_name || primary), subscription_id: subscriptionId, resource_group: String(azure.resource_group || "") });
        } else if (primary) {
            const w = workspaces.find(w => w.id === primary);
            for (const [field, value] of [["name", azure.workspace_name], ["resource_group", azure.resource_group], ["subscription_id", subscriptionId]]) {
                if (value && w[field] && w[field] !== value && !(field === "name" && w[field] === w.id)) throw new Error("Default workspace metadata conflicts with azure_mcp");
                if (value && (!w[field] || (field === "name" && w[field] === w.id))) w[field] = value;
            }
        }
        if (new Set(workspaces.map((w) => w.id)).size !== workspaces.length) throw new Error(`Duplicate ${key} workspace`);
        return {
            key, tenantId, subscriptionId, connections, workspaces,
            memoryFile: memoryFile(p.memory_file),
            azureMcp: structuredClone(azure),
            triageHomeTenantId: guid(p.triage_home_tenant_id, "triage_home_tenant_id", true),
        };
    });
    return { registered: true, profiles };
}

export async function readRegistry(repoRoot) {
    let text;
    try { text = await readFile(path.join(repoRoot, "config.json"), "utf8"); }
    catch (err) {
        if (err.code === "ENOENT") return { registered: false, profiles: [] };
        throw err;
    }
    return parseRegistry(JSON.parse(text));
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
        memoryFile: memoryFile(c.memory_file), triageHomeTenantId: c.triage_home_tenant_id || "",
        caseId: `case-${randomUUID()}`,
    });
}

export function selectContext(registry, key, workspaceId, caseId = "") {
    if (!registry.registered) return null;
    safeSlug(key);
    const profile = registry.profiles.find((p) => p.key === key);
    if (!profile) throw new Error("Unknown tenant profile");
    const id = workspaceId ? guid(workspaceId, "workspace ID") : "";
    if (profile.workspaces.length > 1 && !id) throw new Error("Explicit workspace selection required");
    const workspace = id ? profile.workspaces.find((w) => w.id === id) : profile.workspaces[0] || null;
    if (id && !workspace) throw new Error("Workspace does not belong to selected profile");
    if (caseId && !SLUG.test(caseId)) throw new Error("Case must be a lowercase safe slug (1–64 characters)");
    return freeze({
        ...structuredClone(profile), workspace: workspace ? { ...workspace } : null,
        caseId: caseId || `case-${randomUUID()}`,
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

export function launchEnvelope(binding) {
    const c = binding.context;
    return [
        "MISSION CONTROL — FROZEN LAUNCH CONTEXT (not proof of authentication)",
        JSON.stringify({ ...bindingFields(binding), subscriptionId: c?.subscriptionId || "",
            workspace: c?.workspace || null, connections: c?.connections || {}, azure_mcp: c?.azureMcp || {},
            triage_home_tenant_id: c?.triageHomeTenantId || "", memory_file: c?.memoryFile || "" }),
        c && !c.legacy ? "Use only this profile, workspace, case and named connections. Never fall back to top-level config, another profile, mutable UI selection, shared memory or another workspace. Use scripts/tenant_context.py create --profile <captured-profile> --workspace <captured-workspace-id> --case <captured-case-id> --lookback-days <requested-days> --validate-live to persist/validate the canonical context before data access. Then validate that context with validate <context-path> --validate-live. These checks are read-only against the tenant; they create only local case artifacts. Verify the authenticated tenant of EACH required MCP connection separately; MCP auth remains unverified by the CLI. A connection name, server/header label or Azure CLI login does NOT prove MCP authentication."
            : "Legacy single-tenant mode: validate the configured tenant and authenticated data connections before access.",
        "Enumerate available Sentinel workspaces using the selected connection and verify the captured workspace ID belongs to this tenant. If a workspace is not captured, stop for explicit selection when multiple exist. Never auto-select all, switch on failure, or interpret access failures as clean results.",
        c?.triageHomeTenantId && c.triageHomeTenantId !== c.tenantId
            ? "TRIAGE UNAVAILABLE: Triage is home-tenant-bound and its home tenant differs from this profile. Do not query Triage for this target."
            : "Triage can be used only after its authenticated/home tenant is verified to equal this target; otherwise report it unavailable.",
        c?.memoryFile ? `Consult ONLY tenant memory '${c.memoryFile}' under ~/.copilot/memories/repo/. If absent, report unavailable; no cross-tenant fallback.`
            : "No explicit profile memory configured. Do not consult a generic or another tenant's memory.",
        c && !c.legacy ? `Write reports only below reports/tenants/${c.key}/${c.caseId}/; do not browse other tenants' reports.` : "",
        "When recording this result, invoke_canvas_action record_finding with ALL these exact correlation fields:",
        JSON.stringify(bindingFields(binding)),
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
        const row = { ...bindingFields(binding), skill: binding.skill, status,
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
