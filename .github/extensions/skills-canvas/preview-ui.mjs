// Synthetic browser fixture: no config.json, SDK, Python, auth or state writes.
// Stops automatically after two minutes; Ctrl-C can stop it earlier.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { renderPage } from "./ui.mjs";
import { parseManifest, DOMAIN_ICONS, LOOKBACK_OPTIONS, OUTPUT_MODES, composePrompt, needsEntity } from "./manifest.mjs";
import { parseRegistry, selectContext, LaunchBindings, bindingFields } from "./tenant-context.mjs";
import { randomUUID } from "node:crypto";

const registry = parseRegistry({ tenants: {
    "demo-alpha": {
        tenant_id: "11111111-1111-4111-8111-111111111111",
        sentinel_workspace_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        memory_file: "demo-alpha-context.md", connections: { data_lake: "demo-alpha-lake" },
    },
    "demo-beta": {
        tenant_id: "22222222-2222-4222-8222-222222222222",
        sentinel_workspace_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        memory_file: "demo-beta-context.md", connections: { graph: "demo-beta-graph" },
    },
} });
const manifest = parseManifest(await readFile(new URL("../../manifests/discovery-manifest.yaml", import.meta.url), "utf8"));
const skills = manifest.skills.filter(s => s.prompt).map(s => ({
    ...s, hasEntity: needsEntity(s), launchPrompt: composePrompt(s, ""), fleet: null,
}));
const launches = new LaunchBindings(), statuses = new Map();
let selected = null, revision = randomUUID(), prefs = {};
const scope = () => ({ ...registry, selected, revision });
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
                selected = selectContext(registry, body.profile, body.workspaceId, body.caseId);
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
                if (!selected || !body.targets?.length || !body.request?.trim()) throw new Error("Select context, targets and a hunt request");
                const results = body.targets.map(t => {
                    const c = selectContext(registry, t.profile, t.workspaceId, body.caseId);
                    const b = launches.capture(c, "cross-tenant-hunt", "preview");
                    const binding = bindingFields(b);
                    statuses.set(binding.correlationId, {
                        ...binding, status: "unavailable",
                        detail: "Synthetic failure: secure context requires POSIX O_NOFOLLOW/O_DIRECTORY/dir_fd; no unsafe fallback. No hunt executed.",
                    });
                    return { ok: true, profile: c.key, binding };
                });
                respond(res, 200, { ok: true, results }); return;
            }
            case "/api/hunt-status":
                respond(res, 200, { hunts: body.bindings.map(b => {
                    launches.require(b, "preview"); return statuses.get(b.correlationId);
                }) }); return;
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
