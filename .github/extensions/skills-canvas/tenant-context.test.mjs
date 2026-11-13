import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, writeFile, readFile, rm, symlink } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as vm from "node:vm";
import { parseRegistry, selectContext, safeSlug, stateScope, LaunchBindings, bindingFields, launchEnvelope,
    inTenant, currentTenant, huntStatuses, updateHuntStatus } from "./tenant-context.mjs";
import { stateRoot, migrateLegacyState } from "./paths.mjs";
import { addFinding, loadFindings, archiveFindings, listArchives } from "./findings.mjs";
import { savePrefs, loadPrefs } from "./prefs.mjs";
import { addCosting, loadCosting } from "./costing.mjs";
import { listReports, reportMatchesTenant } from "./reports.mjs";
import { renderPage } from "./ui.mjs";

const T1 = "11111111-1111-4111-8111-111111111111";
const T2 = "22222222-2222-4222-8222-222222222222";
const W1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const W2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const W3 = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const config = () => ({ tenants: {
    alpha: { tenant_id: T1, workspaces: [{ id: W1, name: "Alpha workspace" }, { id: W3, name: "Second workspace" }],
        memory_file: "alpha-memory.md", connections: { data_lake: "alpha-lake", graph: "alpha-graph" } },
    beta: { tenant_id: T2, sentinel_workspace_id: W2, memory_file: "beta-memory.md",
        connections: { graph: "beta-graph", triage: "home-triage" }, triage_home_tenant_id: T1 },
} });
const contexts = () => {
    const r = parseRegistry(config());
    return [selectContext(r, "alpha", W1, "case-a"), selectContext(r, "beta", W2, "case-b")];
};
async function fixture(fn) {
    const root = path.join(process.cwd(), ".mission-control", "canvas-tests", randomUUID());
    await mkdir(root, { recursive: true });
    try { return await fn(root); } finally { await rm(root, { recursive: true, force: true }); }
}

test("registry selections reject traversal, implicit multi-workspace and foreign workspace IDs", () => {
    const registry = parseRegistry(config());
    assert.throws(() => selectContext(registry, undefined, W1), /slug/);
    for (const slug of ["../beta", "/beta", "alpha/beta", "__proto__", "constructor", "Alpha"]) {
        assert.throws(() => safeSlug(slug), /slug/);
    }
    assert.throws(() => selectContext(registry, "alpha"), /Explicit workspace/);
    assert.throws(() => selectContext(registry, "alpha", W2), /does not belong/);
    assert.throws(() => selectContext(registry, "missing", W1), /Unknown/);
    assert.throws(() => selectContext(registry, "alpha", W1, "../case"), /Case/);
    assert.equal(selectContext(registry, "beta", "", "case-b").workspace.id, W2);
    assert.throws(() => stateRoot({ repoRoot: ".", tenantKey: "../beta", tenantFingerprint: "1234567890123456" }), /Invalid/);
});

test("malformed registries fail closed and connection labels never imply auth", () => {
    for (const tenants of [null, [], "bad", { alpha: null }, { alpha: { tenant_id: "bad" } }]) {
        assert.throws(() => parseRegistry({ tenants }));
    }
    const bad = config(); bad.tenants.alpha.connections.graph = "https://credentials.example";
    assert.throws(() => parseRegistry(bad), /connections/);
    const mismatch = config(); mismatch.tenants.alpha.azure_mcp = { tenant: T2 };
    assert.throws(() => parseRegistry(mismatch), /conflicts/);
    const secret = config(); secret.tenants.alpha.token = "not-a-real-secret";
    assert.throws(() => parseRegistry(secret), /Unknown profile/);
    const [a, b] = contexts();
    const binding = new LaunchBindings().capture(b, "cross-tenant-hunt", "s");
    const prompt = launchEnvelope(binding);
    assert.match(prompt, /TRIAGE UNAVAILABLE/);
    assert.match(prompt, /MCP auth remains unverified/);
    assert.match(prompt, /beta-memory\.md/);
    assert.doesNotMatch(prompt, /alpha-memory\.md/);
    assert.equal(a.connections.graph, "alpha-graph");
});

test("findings are correlated with immutable original launch, not mutable selection", async () => {
    const [a, b] = contexts();
    const launches = new LaunchBindings();
    const binding = launches.capture(a, "ioc-investigation", "session");
    const fields = bindingFields(binding);
    const selected = b;
    assert.equal(selected.key, "beta");
    assert.equal(launches.require(fields, "session").context.key, "alpha");
    assert.throws(() => launches.require({ ...fields, profile: "beta" }, "session"), /does not match/);
    assert.throws(() => launches.require({ ...fields, workspaceId: W2 }, "session"), /does not match/);
    assert.throws(() => launches.require({ ...fields, caseId: "case-b" }, "session"), /does not match/);
    assert.throws(() => launches.require({}, "session"), /Unknown/);
    assert.throws(() => launches.require(fields, "other-session"), /Unknown/);
    assert.throws(() => { binding.context.connections.graph = "beta-graph"; }, TypeError);
    const observed = await Promise.all([a, b].map(c => inTenant(c, async () => {
        await new Promise(resolve => setImmediate(resolve));
        return currentTenant().key;
    })));
    assert.deepEqual(observed, ["alpha", "beta"]);
});

test("tenant findings, archives, preferences, costing, statuses and report caches stay isolated", () => fixture(async root => {
    const [a, b] = contexts();
    const sa = stateScope(root, a), sb = stateScope(root, b);
    await addFinding(sa, { title: "Alpha evidence", severity: "high", summary: "Observed", context: { profile: "alpha" } });
    await savePrefs(sa, { "mc.fav.skills": '["ioc-investigation"]' });
    await addCosting(sa, { id: "cost-a", skill: "ioc-investigation", creditsNaiu: 1000000000 });
    const binding = new LaunchBindings().capture(a, "cross-tenant-hunt", "s");
    await updateHuntStatus(root, binding, "error", "Authentication denied");
    assert.equal((await loadFindings(sa))[0].context.profile, "alpha");
    assert.deepEqual(await loadFindings(sb), []);
    assert.deepEqual(await loadPrefs(sb), {});
    assert.deepEqual(await loadCosting(sb), []);
    assert.deepEqual(await huntStatuses(root, b), []);
    assert.equal((await huntStatuses(root, a))[0].status, "error");
    await archiveFindings(sa);
    assert.equal((await listArchives(sa)).length, 1);
    assert.deepEqual(await listArchives(sb), []);
    for (const c of [a, b]) {
        const dir = path.join(root, "reports", "tenants", c.key, c.caseId);
        await mkdir(dir, { recursive: true }); await writeFile(path.join(dir, "report.md"), c.key);
        await writeFile(path.join(dir, "context.json"), JSON.stringify({ schema_version: 1, profile: c.key,
            tenant_id: c.tenantId, case_id: c.caseId, report_dir: `reports/tenants/${c.key}/${c.caseId}` }));
    }
    const ra = await listReports(root, { tenantKey: "alpha", tenantId: a.tenantId });
    const rb = await listReports(root, { tenantKey: "beta", tenantId: b.tenantId });
    assert.equal(ra.files.length, 1); assert.equal(rb.files.length, 1);
    assert.match(ra.files[0].path, /^reports\/tenants\/alpha\//);
    assert.match(rb.files[0].path, /^reports\/tenants\/beta\//);
    assert.equal(await reportMatchesTenant(root, ra.files[0].path, a.key, b.tenantId), false);
    assert.deepEqual((await listReports(root, { tenantKey: "alpha", tenantId: b.tenantId })).files, [],
        "reassigning a profile slug must not expose the prior customer's reports, including cached listings");
    await rm(path.join(root, "reports", "tenants", "alpha"), { recursive: true });
    await symlink(path.join(root, "reports", "tenants", "beta"), path.join(root, "reports", "tenants", "alpha"));
    assert.deepEqual((await listReports(root, { tenantKey: "alpha", tenantId: a.tenantId, refresh: true })).files, []);
}));

test("legacy absent/empty registry remains legacy; legacy data is never adopted by a customer", () => fixture(async root => {
    assert.equal(parseRegistry({}).registered, false);
    assert.equal(parseRegistry({ tenants: {} }).registered, false);
    const old = path.join(root, ".github", "extensions", "skills-canvas", "state");
    await mkdir(old, { recursive: true });
    await writeFile(path.join(old, "findings.json"), '[{"id":"legacy","title":"Unassigned legacy evidence"}]');
    assert.deepEqual(migrateLegacyState(root), ["findings.json"]);
    assert.equal((await loadFindings(root))[0].id, "legacy");
    const [a] = contexts();
    assert.deepEqual(await loadFindings(stateScope(root, a)), []);
    const reassigned = { ...a, tenantId: T2 };
    assert.notEqual(stateRoot(stateScope(root, a)), stateRoot(stateScope(root, reassigned)));
}));

test("error findings cannot turn into clean follow-ups; rendered client JS parses", () => fixture(async root => {
    const f = await addFinding(root, { title: "Unavailable", status: "error", severity: "clean",
        entities: [{ type: "ip", value: "192.0.2.1" }] });
    assert.equal(f.severity, "info");
    assert.deepEqual(f.recommended, []);
    const html = renderPage({}, { registered: true, profiles: parseRegistry(config()).profiles, revision: "revision" });
    const js = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));
    assert.doesNotThrow(() => new vm.Script(js));
    assert.match(html, /id="profileSelect"/);
    assert.match(html, /id="crossTargets"/);
    assert.match(html, /id="crossRequest"/);
    assert.match(html, /id="scopeBanner"/);
    assert.match(html, /O_NOFOLLOW/);
    assert.match(html, /Shared chat\/model context and tool authentication are NOT isolated/);
}));

test("core-created canonical context loads and validates the exact frozen canvas target",
    { skip: !process.env.MC_TEST_PYTHON && "Set MC_TEST_PYTHON to the configured interpreter to check the Python boundary" }, () => fixture(async root => {
        await writeFile(path.join(root, "config.json"), JSON.stringify(config()));
        const [c] = contexts();
        const script = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../scripts/tenant_context.py");
        const created = spawnSync(process.env.MC_TEST_PYTHON, [script, "--repo-root", root, "create",
            "--profile", c.key, "--workspace", c.workspace.id, "--case", c.caseId, "--lookback-days", "7"], { encoding: "utf8" });
        assert.equal(created.status, 0, created.stderr || created.stdout);
        const result = JSON.parse(created.stdout);
        assert.equal(result.mode, "offline");
        const manifest = JSON.parse(await readFile(result.context_path, "utf8"));
        assert.equal(manifest.profile, c.key); assert.equal(manifest.tenant_id, c.tenantId);
        assert.equal(manifest.workspace.id, c.workspace.id); assert.equal(manifest.case_id, c.caseId);
        assert.equal(manifest.memory_file, c.memoryFile);
        assert.equal(manifest.report_dir, `reports/tenants/${c.key}/${c.caseId}`);
        assert.deepEqual(Object.keys(manifest).sort(), ["schema_version", "profile", "tenant_id", "workspace",
            "case_id", "lookback_days", "connections", "report_dir", "created_at", "memory_file", "triage_home_tenant_id"].sort());
        const validated = spawnSync(process.env.MC_TEST_PYTHON, [script, "--repo-root", root, "validate", result.context_path], { encoding: "utf8" });
        assert.equal(validated.status, 0, validated.stderr || validated.stdout);
        assert.equal(JSON.parse(validated.stdout).ok, true);
    }));

// Evaluate the actual extension with only the SDK boundary stubbed. All HTTP
// handlers, storage, prompts, queueing and actions below are production code.
async function runtime(root) {
    const sent = [], events = new Map();
    let canvas;
    const session = { sessionId: "test-session", send: async value => { sent.push(value); },
        log: async () => {}, on: (name, fn) => events.set(name, fn) };
    const context = vm.createContext({ console, process, URL, Buffer, structuredClone,
        setTimeout, clearTimeout, setInterval, clearInterval });
    const modules = new Map();
    async function resolve(specifier, parent) {
        const key = specifier.startsWith(".") ? new URL(specifier, parent.identifier).href : specifier;
        if (modules.has(key)) return modules.get(key);
        const promise = (async () => {
            if (key === "@github/copilot-sdk/extension") {
                return new vm.SyntheticModule(["joinSession", "createCanvas"], function () {
                    this.setExport("joinSession", async () => session);
                    this.setExport("createCanvas", definition => { canvas = definition; return definition; });
                }, { context, identifier: key });
            }
            if (key.startsWith("node:")) {
                const namespace = await import(key);
                return new vm.SyntheticModule(Object.keys(namespace), function () {
                    for (const k of Object.keys(namespace)) this.setExport(k, namespace[k]);
                }, { context, identifier: key });
            }
            const source = await readFile(new URL(key), "utf8");
            return new vm.SourceTextModule(source, { context, identifier: key,
                initializeImportMeta(meta) {
                    meta.url = key.endsWith("/extension.mjs")
                        ? new URL("file://" + path.join(root, ".github/extensions/skills-canvas/extension.mjs")).href : key;
                } });
        })();
        modules.set(key, promise);
        return promise;
    }
    const entry = await resolve(new URL("./extension.mjs", import.meta.url).href, null);
    await entry.link(resolve); await entry.evaluate();
    const opened = await canvas.open({ instanceId: "test-panel" });
    return { sent, events, canvas, url: opened.url, close: () => canvas.onClose({ instanceId: "test-panel" }) };
}

test("HTTP fanout freezes selected targets; original token routes late findings and stale pages fail closed",
    { skip: !vm.SourceTextModule && "Run with --experimental-vm-modules for SDK-boundary integration" }, () => fixture(async root => {
        await writeFile(path.join(root, "config.json"), JSON.stringify(config()));
        await mkdir(path.join(root, ".github", "manifests"), { recursive: true });
        await writeFile(path.join(root, ".github", "manifests", "discovery-manifest.yaml"),
            'skills:\n- name: ioc-investigation\n  prompt: Investigate {entity}\n  domains:\n  - identity\nqueries:\n');
        for (const c of contexts()) {
            const dir = path.join(root, "reports", "tenants", c.key, c.caseId);
            await mkdir(dir, { recursive: true });
            await writeFile(path.join(dir, "context.json"), JSON.stringify({ schema_version: 1, profile: c.key,
                tenant_id: c.tenantId, case_id: c.caseId, report_dir: `reports/tenants/${c.key}/${c.caseId}` }));
            await writeFile(path.join(dir, "report.md"), `Synthetic ${c.key}-only report`);
        }
        const app = await runtime(root);
        let revision = "";
        async function request(url, body, token = revision) {
            const res = await fetch(new URL(url, app.url), {
                method: body === undefined ? "GET" : "POST", headers: { "Content-Type": "application/json", "X-MC-Context": token },
                ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            });
            return { code: res.status, data: await res.json() };
        }
        try {
            const html = await (await fetch(app.url)).text();
            revision = JSON.parse(/const MC_SCOPE = (.*);/.exec(html)[1]).revision;
            assert.equal((await request("/api/findings")).code, 400);
            assert.equal(app.sent.length, 0);
            const selection = await request("/api/context", { profile: "alpha", workspaceId: W1, caseId: "case-a" });
            assert.equal(selection.data.ok, true);
            const oldRevision = revision; revision = selection.data.context.revision;
            assert.equal(app.sent.length, 0, "picker must not query or authenticate");
            assert.equal((await request("/api/prefs", { patch: { "mc.test": "old" } }, oldRevision)).code, 409);
            assert.equal((await request("/api/cross-tenant-hunt", { targets: [], request: "hunt" })).code, 500);
            const batch = await request("/api/cross-tenant-hunt", { targets: [{ profile: "alpha", workspaceId: W1 },
                { profile: "beta", workspaceId: W2 }], caseId: "case-hunt", request: "Hunt 192.0.2.1", lookbackDays: 7 });
            assert.equal(batch.data.ok, true);
            assert.equal(batch.data.results.length, 2);
            assert.equal(app.sent.length, 1);
            const [a, b] = batch.data.results.map(r => r.binding);
            assert.equal(a.profile, "alpha"); assert.equal(b.profile, "beta");
            const alphaActivity = await request("/api/activity");
            assert.equal(alphaActivity.data.queued.length, 0, "another tenant's queued activity must not appear on Alpha's board");
            const record = app.canvas.actions.find(action => action.name === "record_finding").handler;
            assert.equal((await record({ input: { title: "No token", severity: "clean" } })).ok, false);
            const result = await record({ input: { ...b, title: "Beta auth unavailable", severity: "clean",
                status: "unavailable", summary: "Graph connection tenant could not be verified" } });
            assert.equal(result.ok, true);
            const [ca, cb] = contexts();
            assert.deepEqual(await loadFindings(stateScope(root, ca)), []);
            const findings = await loadFindings(stateScope(root, cb));
            assert.equal(findings[0].context.correlationId, b.correlationId);
            assert.equal(findings[0].status, "unavailable"); assert.equal(findings[0].severity, "info");
            assert.deepEqual(findings[0].recommended, []);
            assert.match(app.sent[0].prompt, /alpha-memory\.md/);
            assert.doesNotMatch(app.sent[0].prompt, /beta-memory\.md/);
            assert.match(app.sent[0].prompt, new RegExp(a.correlationId));
            let switched;
            for (let attempt = 0; attempt < 10; attempt++) {
                app.events.get("session.error")({ data: { message: "Synthetic executor stopped" } });
                await new Promise(resolve => setTimeout(resolve, 10));
                switched = await request("/api/context", { profile: "beta", workspaceId: W2, caseId: "case-b" });
                if (switched.data.ok) break;
            }
            assert.equal(switched.data.ok, true);
            revision = switched.data.context.revision;
            const late = await record({ input: { ...a, title: "Late Alpha evidence", severity: "high",
                status: "complete", summary: "Evidence from the original frozen Alpha investigation" } });
            assert.equal(late.ok, true);
            const alpha = await loadFindings(stateScope(root, ca));
            assert.equal(alpha[0].title, "Late Alpha evidence");
            const betaBoard = await request("/api/findings");
            assert.equal(betaBoard.data.findings.length, 1);
            assert.equal(betaBoard.data.findings[0].title, "Beta auth unavailable");
            const betaActivity = await request("/api/activity");
            assert.ok(betaActivity.data.recent.every(r => r.binding.context.key === "beta"));
            const preview = async p => fetch(new URL("/api/report?path=" + encodeURIComponent(p), app.url),
                { headers: { "X-MC-Context": revision } });
            assert.equal((await preview("reports/tenants/alpha/case-a/report.md")).status, 403);
            const ownPreview = await preview("reports/tenants/beta/case-b/report.md");
            assert.equal(ownPreview.status, 200);
            assert.match(await ownPreview.text(), /beta-only report/);
            assert.equal((await request("/api/prefs", { patch: { "mc.test": "stale-alpha" } }, selection.data.context.revision)).code, 409);
            const forged = await record({ input: { ...a, profile: "beta", title: "Wrong tenant", severity: "high" } });
            assert.equal(forged.ok, false);
            const launch = app.canvas.actions.find(action => action.name === "launch_skill").handler;
            assert.equal((await launch({ input: { skill: "ioc-investigation", entity: "192.0.2.1" } })).ok, false);
            const followup = await launch({ input: { ...a, skill: "ioc-investigation", entity: "192.0.2.1" } });
            assert.equal(followup.ok, true);
            assert.equal(followup.binding.profile, "alpha", "follow-up must retain its parent context, not the current Beta picker");
            assert.equal((await request("/api/data")).data.context.selected.key, "beta");
            app.events.get("session.error")({ data: { message: "Synthetic executor stopped" } });
        } finally { await app.close(); }
    }));
