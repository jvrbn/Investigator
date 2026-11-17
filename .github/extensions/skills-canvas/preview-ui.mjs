// Synthetic browser fixture: no config.json, SDK, Python, auth or state writes.
// Stops automatically after two minutes; Ctrl-C can stop it earlier.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { renderPage } from "./ui.mjs";
import { parseManifest, DOMAIN_ICONS, LOOKBACK_OPTIONS, OUTPUT_MODES, composePrompt, needsEntity } from "./manifest.mjs";
import { parseRegistry, selectContext, publicProfile, LaunchBindings, bindingFields, launchEnvelope } from "./tenant-context.mjs";
import { CAPABILITIES } from "./contract.mjs";
import { planHunt, huntPrompt } from "./hunt.mjs";
import { randomUUID } from "node:crypto";

const registry = parseRegistry({ tenants: {
    "demo-alpha": {
        tenant_id: "11111111-1111-4111-8111-111111111111",
        sentinel_workspace_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        memory_file: "demo-alpha-context.md", connections: { data_lake: "demo-alpha-lake", triage: "demo-alpha-triage" },
        triage_home_tenant_id: "11111111-1111-4111-8111-111111111111",
    },
    "demo-beta": {
        tenant_id: "22222222-2222-4222-8222-222222222222",
        sentinel_workspace_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        memory_file: "demo-beta-context.md", connections: { graph: "demo-beta-graph" },
    },
    // A guest tenant with no Sentinel workspace: Defender-only, Triage is home-tenant-only.
    "demo-guest": {
        tenant_id: "33333333-3333-4333-8333-333333333333",
        memory_file: "demo-guest-context.md", connections: { graph: "demo-guest-graph" },
        triage_home_tenant_id: "11111111-1111-4111-8111-111111111111",
    },
} });
const manifest = parseManifest(await readFile(new URL("../../manifests/discovery-manifest.yaml", import.meta.url), "utf8"));
const skills = manifest.skills.filter(s => s.prompt).map(s => ({
    ...s, hasEntity: needsEntity(s), launchPrompt: composePrompt(s, ""), fleet: null,
}));
const launches = new LaunchBindings(), statuses = new Map();
let selected = null, revision = randomUUID(), prefs = {};
const scope = () => ({
    registered: registry.registered, profiles: registry.profiles.map(publicProfile), selected, revision,
    capabilities: Object.entries(CAPABILITIES).map(([name, spec]) => ({ name, proof: spec.proof, scoped: spec.scoped })),
});
const respond = (res, code, data) => {
    res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    res.end(JSON.stringify(data));
};
const server = createServer(async (req, res) => {
    try {
        const url = new URL(req.url, "http://127.0.0.1");
        if (url.pathname === "/") {
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
            res.end(renderPage(prefs, scope())); return;
        }
        if ((req.headers["x-mc-context"] || url.searchParams.get("mcContext")) !== revision) {
            respond(res, 409, { ok: false, error: "Synthetic fixture context changed; reload" }); return;
        }
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
        switch (url.pathname) {
            case "/api/context":
                selected = selectContext(registry, body.profile, body.workspaceId, body.caseId, { defenderOnly: body.defenderOnly === true });
                revision = randomUUID(); prefs = {};
                respond(res, 200, { ok: true, context: scope() }); return;
            case "/api/data":
                respond(res, 200, {
                    error: "SYNTHETIC UI FIXTURE — no live tenant, authentication, queries or persisted state.",
                    skills, queries: [], recent: [], context: scope(),
                    tenant: { name: selected?.key || "Selection required", memoryFile: selected?.memoryFile || "" },
                    domains: Object.entries(DOMAIN_ICONS).map(([id, icon]) => ({
                        id, icon, skillCount: skills.filter(s => s.domains?.includes(id)).length, queryCount: 0,
                    })),
                    lookbackOptions: LOOKBACK_OPTIONS, outputModes: OUTPUT_MODES, defaultOutput: "inline",
                }); return;
            case "/api/prefs":
                prefs = { ...prefs, ...body.patch }; respond(res, 200, { ok: true, prefs }); return;
            case "/api/cross-tenant-hunt": {
                if (!selected) throw new Error("Select a context first");
                const plan = planHunt(registry, body);
                const results = plan.targets.map(({ context: c, coverage, unavailable }) => {
                    const row = {
                        profile: c.key, workspaceId: c.workspace?.id ?? "", defenderOnly: c.defenderOnly, caseId: c.caseId,
                        huntId: plan.huntId, window: c.window, requiredCapabilities: coverage.required,
                        unsupportedCapabilities: coverage.unsupported,
                    };
                    if (plan.mode === "handoff" && !unavailable) {
                        const detached = { correlationId: "", context: c, skill: "cross-tenant-hunt", sessionId: "", createdAt: Date.now() };
                        return { ...row, ok: true, status: "handoff",
                            prompt: launchEnvelope(detached, { handoff: true }) + "\n\n---\n" + huntPrompt(plan, { handoff: true }) };
                    }
                    const b = launches.capture(c, "cross-tenant-hunt", "preview");
                    const binding = bindingFields(b);
                    const detail = unavailable ||
                        "Synthetic failure: secure context requires POSIX O_NOFOLLOW/O_DIRECTORY/dir_fd; no unsafe fallback. No hunt executed.";
                    statuses.set(binding.correlationId, { ...binding, huntId: plan.huntId, status: "unavailable", detail });
                    return { ...row, ok: false, status: "unavailable", error: detail, binding };
                });
                respond(res, 200, { ok: results.every(r => r.ok), mode: plan.mode, huntId: plan.huntId, window: plan.window, results }); return;
            }
            case "/api/hunt-status":
                respond(res, 200, { hunts: body.bindings.map(b => {
                    launches.require(b, "preview"); return statuses.get(b.correlationId);
                }) }); return;
            case "/api/readiness":
                // The fixture records no ledger: nothing is ever reported as usable.
                if (Array.isArray(body.bindings)) {
                    respond(res, 200, { readiness: body.bindings.map(b => { launches.require(b, "preview"); return { binding: b, readiness: null }; }) }); return;
                }
                respond(res, 200, { evidence: (body.targets || []).map(t => ({
                    profile: t.profile, workspaceId: t.workspaceId || "", defenderOnly: t.defenderOnly === true,
                    evidence: { cases_scanned: 0, capabilities: {}, usable: [], advisory: true },
                })) }); return;
            case "/api/activity":
                respond(res, 200, { active: [], queued: [], recent: [], autopilot: null, autopilots: [] }); return;
            case "/api/findings":
            case "/api/findings/all":
                respond(res, 200, { findings: [], items: [], summary: { total: 0 } }); return;
            case "/api/findings/archives": respond(res, 200, { archives: [] }); return;
            case "/api/costing": respond(res, 200, { costing: [], summary: {} }); return;
            case "/api/reports": respond(res, 200, { files: [], dirs: [], total: 0 }); return;
            case "/api/autopilot": respond(res, 200, { autopilot: { status: "off", trail: [] }, limits: {}, board: [] }); return;
            case "/api/compose": respond(res, 200, { ok: true, skill: body.skill, prompt: "SYNTHETIC PREVIEW ONLY — launch disabled." }); return;
            default: respond(res, 400, { ok: false, error: "Synthetic fixture: live actions and tenant access are disabled" });
        }
    } catch (error) { respond(res, 400, { ok: false, error: error.message }); }
});
server.listen(0, "127.0.0.1", () => {
    console.log(`Synthetic Mission Control: http://127.0.0.1:${server.address().port}/ (auto-stop: 120s)`);
});
const timer = setTimeout(() => server.close(), 120000);
server.on("close", () => clearTimeout(timer));
process.once("SIGINT", () => server.close());
process.once("SIGTERM", () => server.close());
