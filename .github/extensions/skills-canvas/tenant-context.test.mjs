import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, writeFile, readFile, readdir, rm, symlink, realpath } from "node:fs/promises";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as vm from "node:vm";
import { parseRegistry, selectContext, safeSlug, stateScope, LaunchBindings, bindingFields, launchEnvelope,
    inTenant, currentTenant, huntStatuses, updateHuntStatus, publicProfile } from "./tenant-context.mjs";
import { CAPABILITIES, LEDGER_NAME, ContractError, blockedByStaticLimits, huntChildId, huntWindow, isHuntChild,
    lookbackDays as checkedLookback, parseUtc, scopeFromContext, scopeFromManifest, validHuntId, validateRecord } from "./contract.mjs";
import { ledgerReadiness, readCaseLedger, readTargetEvidence } from "./ledger.mjs";
import { planHunt, huntPrompt, MAX_HUNT_TARGETS } from "./hunt.mjs";
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

test("the same incident number in two tenants stays two unrelated findings", () => fixture(async root => {
    const [a, b] = contexts();
    const sa = stateScope(root, a), sb = stateScope(root, b);
    const known = new Set(["incident-investigation"]);
    const incident = [{ type: "incident", value: "12345" }];
    await addFinding(sa, { title: "Incident 12345", severity: "high", summary: "Alpha evidence only",
        entities: incident, context: { profile: "alpha" } }, known);
    await addFinding(sb, { title: "Incident 12345", severity: "clean", summary: "Beta evidence only",
        entities: incident, context: { profile: "beta" } }, known);
    const [fa] = await loadFindings(sa), [fb] = await loadFindings(sb);
    assert.equal((await loadFindings(sa)).length, 1);
    assert.equal((await loadFindings(sb)).length, 1);
    assert.deepEqual([fa.severity, fa.context.profile, fb.severity, fb.context.profile], ["high", "alpha", "clean", "beta"]);
    assert.match(fa.recommended[0].prompt, /Alpha evidence only/);
    assert.doesNotMatch(fa.recommended[0].prompt, /Beta evidence only/);
    assert.match(fb.recommended[0].prompt, /Beta evidence only/);
    assert.doesNotMatch(fb.recommended[0].prompt, /Alpha evidence only/);
    await archiveFindings(sa);
    assert.deepEqual(await loadFindings(sa), []);
    assert.equal((await loadFindings(sb)).length, 1, "archiving one tenant must not touch the other's finding");
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
            "case_id", "lookback_days", "connections", "report_dir", "created_at", "memory_file", "triage_home_tenant_id",
            "window", "hunt_id", "capabilities"].sort());
        assert.equal(manifest.schema_version, 2);
        assert.equal(manifest.hunt_id, null);
        assert.deepEqual(manifest.capabilities, c.capabilities);
        assert.deepEqual(scopeFromManifest(manifest).workspaceId, scopeFromContext(c).workspaceId);
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
    const context = vm.createContext({ console, process, URL, Buffer, structuredClone, TextDecoder, TextEncoder,
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

// ── Shared contract fixtures: tests/fixtures/tenant_contract ─────────────────
// tests/test_tenant_context.py pins the same files, so a drift in either
// implementation fails whichever suite still follows the fixture.

const shared = async name => JSON.parse(await readFile(
    new URL(`../../../tests/fixtures/tenant_contract/${name}.json`, import.meta.url), "utf8"));

// The fields Python (`parsed_profile`) and this parser must agree on.
const parsedProfile = p => ({
    tenant_id: p.tenantId, subscription_id: p.subscriptionId || null,
    sentinel_workspace_id: p.sentinelWorkspaceId || null, workspaces: p.workspaces,
    connections: { data_lake: p.connections.data_lake ?? null, graph: p.connections.graph ?? null, triage: p.connections.triage ?? null },
    memory_file: p.memoryFile || null, triage_home_tenant_id: p.triageHomeTenantId || null,
    sit_mapping: Object.fromEntries(p.mappings.sit), label_mapping: Object.fromEntries(p.mappings.label),
    sit_priority: Object.fromEntries(p.mappings.priority),
});

test("registry fixture: the JavaScript parser normalizes and rejects exactly like the Python contract", async () => {
    const { valid, legacy, invalid } = await shared("registry");
    const registry = parseRegistry(structuredClone(valid.config));
    assert.equal(registry.registered, true);
    assert.deepEqual(Object.fromEntries(registry.profiles.map(p => [p.key, parsedProfile(p)])), valid.expected);
    assert.ok(invalid.length >= 40);
    for (const entry of invalid) assert.throws(() => parseRegistry(structuredClone(entry.config)), undefined, entry.name);
    for (const entry of legacy) assert.deepEqual(parseRegistry(entry.config), { registered: false, profiles: [] }, entry.name);
});

test("tenant-local mapping tables stay out of anything sent to the UI or a prompt", async () => {
    const { valid } = await shared("registry");
    const registry = parseRegistry(structuredClone(valid.config));
    const contoso = registry.profiles.find(p => p.key === "contoso");
    assert.ok(contoso.mappings.sit.length > 0);
    assert.equal("mappings" in publicProfile(contoso), false);
    const context = selectContext(registry, "contoso", contoso.sentinelWorkspaceId, "case-one");
    assert.equal("mappings" in context, false);
    assert.doesNotMatch(JSON.stringify(context), /Synthetic (SIT|Label)/);
    assert.doesNotMatch(launchEnvelope(new LaunchBindings().capture(context, "ioc-investigation", "s")), /Synthetic (SIT|Label)/);
});

test("window fixture: same collection window, hunt ids and child cases as the Python contract", async () => {
    const w = await shared("windows");
    for (const c of w.valid) {
        assert.deepEqual(huntWindow(c.lookback_days, c.end), { lookback_days: c.lookback_days, start_utc: c.start, end_utc: c.end });
    }
    for (const end of w.invalid_ends) assert.throws(() => huntWindow(7, end), ContractError, JSON.stringify(end));
    for (const days of w.invalid_lookbacks) {
        assert.throws(() => huntWindow(days, "2024-03-01T12:00:00Z"), ContractError, String(days));
        assert.throws(() => checkedLookback(days), ContractError, String(days));
    }
    for (const id of w.valid_hunt_ids) assert.equal(validHuntId(id), id);
    for (const id of w.invalid_hunt_ids) assert.throws(() => validHuntId(id), ContractError, id);
    for (const c of w.children) {
        assert.equal(huntChildId(c.hunt_id, c.index), c.case_id);
        assert.equal(isHuntChild(c.hunt_id, c.case_id), true, c.case_id);
    }
    for (const index of w.invalid_child_indexes) assert.throws(() => huntChildId("hunt-1", index), ContractError, String(index));
    for (const caseId of w.invalid_child_case_ids) assert.equal(isHuntChild("hunt-1", caseId), false, caseId);
    const future = new Date(Date.now() + 3_600_000).toISOString().slice(0, 19) + "Z";
    assert.throws(() => huntWindow(7, future), /future/);
});

// Patch entries copy an earlier record, then apply `set` and `unset`.
function expandRecords(entries) {
    const built = new Map(), expanded = [];
    for (const entry of entries) {
        let record;
        if ("record" in entry) record = structuredClone(entry.record);
        else {
            record = structuredClone(built.get(entry.from));
            Object.assign(record, entry.set ?? {});
            for (const key of entry.unset ?? []) delete record[key];
        }
        built.set(entry.name, record);
        expanded.push([entry, record]);
    }
    return expanded;
}
const ledgerDirectory = (root, scope) => path.join(root, "reports", "tenants", scope.profile, scope.caseId, "ledger");
async function seedLedger(root, scope, files) {
    const directory = ledgerDirectory(root, scope);
    await mkdir(directory, { recursive: true });
    for (const [name, body] of Object.entries(files)) {
        await writeFile(path.join(directory, name), typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
    }
    return directory;
}

test("ledger fixture: the read-only view accepts, ignores and resolves records exactly like the Python reader", async () => {
    const { scenarios } = await shared("ledger");
    assert.equal(scenarios.length, 5);
    for (const scenario of scenarios) {
        await fixture(async root => {
            const scope = scopeFromManifest(scenario.context);
            const now = parseUtc(scenario.now, "now");
            const files = {};
            for (const [entry, record] of expandRecords(scenario.records)) {
                assert.equal(entry.file in files, false, "fixture file names must be unique");
                files[entry.file] = JSON.stringify(record);
                let accepted;
                try { accepted = LEDGER_NAME.test(entry.file) && validateRecord(record, scope, now, entry.file) !== null; }
                catch (err) { assert.ok(err instanceof ContractError, err.stack); accepted = false; }
                assert.equal(accepted, entry.valid, `${scenario.name}: ${entry.name}`);
            }
            await seedLedger(root, scope, files);
            const ready = await ledgerReadiness(root, scope, now);
            const { expect } = scenario;
            assert.equal(ready.ignored_records, expect.ignored, scenario.name);
            assert.deepEqual(ready.blocked, expect.blocked, scenario.name);
            assert.equal(ready.ok, expect.blocked.length === 0, scenario.name);
            assert.deepEqual(Object.keys(expect.effective).sort(), Object.keys(CAPABILITIES).sort());
            for (const [capability, wanted] of Object.entries(expect.effective)) {
                for (const [key, value] of Object.entries(wanted)) {
                    assert.deepEqual(ready.capabilities[capability][key], value, `${scenario.name}: ${capability}.${key}`);
                }
            }
            assert.equal(ready.advisory, true);
            assert.match(ready.authoritative_command, /tenant_context\.py readiness/);
        });
    }
});

// ── The read-only ledger view must never trust the filesystem ────────────────

const NOW = Date.parse("2024-03-02T12:00:00Z");
const sampleRecord = (scope, patch = {}) => ({
    schema_version: 1, kind: "capability_check", profile: scope.profile, tenant_id: scope.tenantId, workspace_id: null,
    case_id: scope.caseId, capability: "tenant_identity", status: "verified", method: "cli_probe",
    checked_at: "2024-03-01T12:00:05Z", expires_at: "2024-03-02T12:00:05Z",
    detail: "Graph organization ID matched the selected tenant", via: null, ...patch,
});
// A name the writer would produce: the record's own second plus `micros`.
const ledgerName = (record, micros = 0) =>
    `${record.checked_at.replace(/[-:]/g, "").slice(0, -1)}${String(micros).padStart(6, "0")}Z-${record.capability}.json`;

test("the read-only ledger view ignores forged, oversize, BOM and special files and never lets them shadow a valid record",
    { timeout: 30_000 }, () => fixture(async root => {
        const scope = scopeFromContext(contexts()[0]);
        const good = sampleRecord(scope);
        const forged = [
            sampleRecord(scope, { tenant_id: T2 }), sampleRecord(scope, { profile: "beta" }),
            sampleRecord(scope, { case_id: "case-b" }), { ...sampleRecord(scope), note: "extra field" },
            sampleRecord(scope, { status: "attested" }), sampleRecord(scope, { method: "agent_attestation", status: "attested" }),
            sampleRecord(scope, { via: "portal" }), sampleRecord(scope, { detail: "token: abcdefghijklmnop" }),
            sampleRecord(scope, { expires_at: "2025-03-02T12:00:05Z" }),
            sampleRecord(scope, { checked_at: "2024-03-02T13:00:00Z", expires_at: "2024-03-03T13:00:00Z" }),
            sampleRecord(scope, { capability: "workspace_arm", workspace_id: W3 }),
        ];
        const files = { [ledgerName(good)]: good };
        forged.forEach((record, index) => { files[ledgerName(record, index + 1)] = record; });
        const newer = micros => ledgerName(good, micros);
        files[newer(900_001)] = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(good))]);
        files[newer(900_002)] = JSON.stringify(good) + " ".repeat(9000);
        files["not-a-ledger-name.json"] = good;
        files[newer(900_003)] = "{not json";
        const planted = 4;
        const directory = await seedLedger(root, scope, files);
        // A symlink and a directory carry valid-looking names; a FIFO would hang a blocking reader.
        await symlink(path.join(directory, ledgerName(good)), path.join(directory, newer(900_004)));
        await mkdir(path.join(directory, newer(900_005)));
        const fifo = spawnSync("mkfifo", [path.join(directory, newer(900_006))]);
        const specials = 2 + (fifo.status === 0 ? 1 : 0);

        const ready = await ledgerReadiness(root, scope, NOW);
        assert.equal(ready.ignored_records, forged.length + planted + specials);
        assert.equal(ready.capabilities.tenant_identity.status, "verified");
        assert.equal(ready.capabilities.tenant_identity.checked_at, good.checked_at);
        assert.equal(ready.capabilities.workspace_arm.status, "unverified", "a record for another workspace must not count");
        assert.deepEqual(ready.blocked, ["workspace_arm"]);
        assert.equal(ready.ok, false);
        assert.deepEqual(ready.usable, ["tenant_identity"]);
        assert.deepEqual(ready.ledger, { present: true, unsafe: false, truncated: false, skipped: 0 });
    }));

test("a symlinked tenant, case or ledger directory is unsafe and yields no records", () => fixture(async root => {
    const scope = scopeFromContext(contexts()[0]);
    const good = sampleRecord(scope);
    const elsewhere = path.join(root, "elsewhere");
    await mkdir(elsewhere, { recursive: true });
    await writeFile(path.join(elsewhere, ledgerName(good)), JSON.stringify(good));

    const caseDirectory = path.join(root, "reports", "tenants", scope.profile, scope.caseId);
    await mkdir(caseDirectory, { recursive: true });
    await symlink(elsewhere, path.join(caseDirectory, "ledger"));
    let view = await readCaseLedger(root, scope, NOW);
    assert.deepEqual([view.unsafe, view.present, view.records], [true, false, {}]);

    await rm(path.join(root, "reports"), { recursive: true, force: true });
    await mkdir(path.join(root, "reports", "tenants", scope.profile), { recursive: true });
    await symlink(elsewhere, path.join(root, "reports", "tenants", scope.profile, scope.caseId));
    view = await readCaseLedger(root, scope, NOW);
    assert.deepEqual([view.unsafe, view.present, view.records], [true, false, {}]);

    await rm(path.join(root, "reports"), { recursive: true, force: true });
    await mkdir(path.join(root, "reports"), { recursive: true });
    await symlink(elsewhere, path.join(root, "reports", "tenants"));
    view = await readCaseLedger(root, scope, NOW);
    assert.deepEqual([view.unsafe, view.present, view.records], [true, false, {}]);

    await rm(path.join(root, "reports"), { recursive: true, force: true });
    view = await readCaseLedger(root, scope, NOW);
    assert.deepEqual([view.unsafe, view.present], [false, false], "an absent ledger is unverified, not unsafe");
    const ready = await ledgerReadiness(root, scope, NOW);
    assert.equal(ready.ok, false);
    assert.deepEqual(ready.blocked, ["tenant_identity", "workspace_arm"]);
    assert.equal(ready.capabilities.tenant_identity.detail, "No check recorded");
    assert.equal((await readCaseLedger(root, { ...scope, caseId: "../case" }, NOW)).unsafe, true);
}));

test("the ledger view reads only the newest files when a ledger is oversized", () => fixture(async root => {
    const scope = scopeFromContext(contexts()[0]);
    const identity = sampleRecord(scope);
    const arm = sampleRecord(scope, { capability: "workspace_arm", workspace_id: W1, checked_at: "2024-03-01T12:00:06Z", expires_at: "2024-03-02T12:00:06Z" });
    await seedLedger(root, scope, { [ledgerName(identity)]: identity, [ledgerName(arm)]: arm });
    const view = await readCaseLedger(root, scope, NOW, { limit: 1 });
    assert.deepEqual([view.skipped, view.truncated, Object.keys(view.records)], [1, true, ["workspace_arm"]]);
}));

test("target evidence is advisory, profile-wide and never borrowed across tenants or workspaces", () => fixture(async root => {
    const scope = scopeFromContext(contexts()[0]);
    const identity = sampleRecord(scope);
    const arm = sampleRecord(scope, { capability: "workspace_arm", workspace_id: W1 });
    await seedLedger(root, scope, { [ledgerName(identity)]: identity, [ledgerName(arm)]: arm });
    const target = { profile: "alpha", tenantId: T1, workspaceId: W1, connections: { data_lake: "alpha-lake" }, triageHomeTenantId: null };

    const own = await readTargetEvidence(root, target, { nowMs: NOW });
    assert.deepEqual([...own.usable].sort(), ["tenant_identity", "workspace_arm"]);
    assert.equal(own.capabilities.tenant_identity.case_id, "case-a");
    assert.equal(own.advisory, true);
    assert.equal(own.cases_scanned, 1);

    const reused = await readTargetEvidence(root, { ...target, tenantId: T2 }, { nowMs: NOW });
    assert.deepEqual(reused.usable, [], "a reused profile slug must not inherit another tenant's evidence");
    const sibling = await readTargetEvidence(root, { ...target, workspaceId: W3 }, { nowMs: NOW });
    assert.deepEqual(sibling.usable, ["tenant_identity"], "another workspace gets only tenant-level evidence");
    const defender = await readTargetEvidence(root, { ...target, workspaceId: null }, { nowMs: NOW });
    assert.deepEqual(defender.usable, ["tenant_identity"]);
    const later = await readTargetEvidence(root, target, { nowMs: Date.parse("2024-03-03T00:00:00Z") });
    assert.deepEqual(later.usable, [], "expired evidence is not usable");
    assert.equal((await readTargetEvidence(root, { ...target, profile: "../beta" }, { nowMs: NOW })).unsafe, true);
    assert.equal((await readTargetEvidence(root, { ...target, profile: "unused" }, { nowMs: NOW })).cases_scanned, 0);
}));

// ── Hunt contexts and the frozen launch envelope ─────────────────────────────

const HUNT_END = "2024-03-01T12:00:00Z";
const huntOptions = { huntId: "hunt-1", lookbackDays: 30, windowEnd: HUNT_END };

test("hunt contexts pin one window, numbered children and explicit capabilities; Defender-only binds no workspace", () => {
    const registry = parseRegistry(config());
    const one = selectContext(registry, "alpha", W1, "hunt-1-01", { ...huntOptions, capabilities: ["data_lake", "workspace_query"] });
    const two = selectContext(registry, "alpha", W3, "hunt-1-02", huntOptions);
    const three = selectContext(registry, "alpha", "", "hunt-1-03", { ...huntOptions, defenderOnly: true });
    const window = { start_utc: "2024-01-31T12:00:00Z", end_utc: HUNT_END };
    for (const c of [one, two, three]) { assert.deepEqual(c.window, window); assert.equal(c.huntId, "hunt-1"); assert.equal(c.lookbackDays, 30); }
    assert.deepEqual(one.capabilities, ["data_lake", "tenant_identity", "workspace_query"]);
    assert.deepEqual(two.capabilities, ["tenant_identity", "workspace_arm"]);
    assert.equal(three.workspace, null);
    assert.equal(three.defenderOnly, true);
    assert.deepEqual(three.capabilities, ["tenant_identity"]);
    assert.equal(new Set([one.caseId, two.caseId, three.caseId]).size, 3, "two workspaces of one tenant need distinct child cases");
    assert.equal(selectContext(registry, "alpha", W1, "case-plain").window, null);

    const bad = (fn, pattern) => assert.throws(fn, pattern);
    bad(() => selectContext(registry, "alpha", W1, "hunt-1-01", { huntId: "hunt-1", lookbackDays: 30 }), /pinned window/);
    bad(() => selectContext(registry, "alpha", W1, "case-a", huntOptions), /hunt case ID/);
    bad(() => selectContext(registry, "alpha", W1, "hunt-2-01", huntOptions), /hunt case ID/);
    bad(() => selectContext(registry, "alpha", W1, "hunt-1-01", { ...huntOptions, lookbackDays: 0 }), ContractError);
    bad(() => selectContext(registry, "alpha", W1, "hunt-1-01", { ...huntOptions, windowEnd: "2024-03-01" }), ContractError);
    bad(() => selectContext(registry, "alpha", W1, "hunt-1-01", { ...huntOptions, defenderOnly: true }), /Defender-only/);
    bad(() => selectContext(registry, "alpha", "", "hunt-1-01", { ...huntOptions, defenderOnly: true, capabilities: ["workspace_query"] }), /require a workspace/);
    bad(() => selectContext(registry, "alpha", W1, "hunt-1-01", { ...huntOptions, capabilities: ["root"] }), /Unknown capability/);
    bad(() => selectContext(registry, "alpha", "", "hunt-1-04", huntOptions), /Explicit workspace/);
    bad(() => selectContext(registry, "alpha", W1, "hunt-1-01", { ...huntOptions, huntId: "Hunt 1" }), ContractError);
});

test("capabilities a target can never provide are reported, never silently dropped", () => {
    const registry = parseRegistry(config());
    const guest = selectContext(registry, "beta", W2, "hunt-1-01", { ...huntOptions, capabilities: ["triage", "graph"] });
    assert.deepEqual(blockedByStaticLimits(scopeFromContext(guest)).map(b => b.capability), ["triage"]);
    assert.match(blockedByStaticLimits(scopeFromContext(guest))[0].reason, /home-tenant/);
    const home = selectContext(registry, "alpha", W1, "hunt-1-02", { ...huntOptions, capabilities: ["data_lake", "graph"] });
    assert.deepEqual(blockedByStaticLimits(scopeFromContext(home)), []);
});

test("the launch envelope freezes exact CLI commands, the shared window and the unsupported capabilities", () => {
    const registry = parseRegistry(config());
    const guest = selectContext(registry, "beta", W2, "hunt-1-01", { ...huntOptions, capabilities: ["graph", "triage"] });
    const envelope = launchEnvelope(new LaunchBindings().capture(guest, "cross-tenant-hunt", "s"));
    const ctx = "reports/tenants/beta/hunt-1-01/context.json";
    // `create` rejects statically unsupported capabilities, so the frozen command never asks for triage.
    assert.match(envelope, new RegExp(`^1\\. python scripts/tenant_context\\.py create --profile beta --workspace ${W2} --case hunt-1-01 ` +
        `--lookback-days 30 --hunt-id hunt-1 --window-end ${HUNT_END} --capability graph --capability tenant_identity --validate-live$`, "m"));
    assert.match(envelope, new RegExp(`^2\\. python scripts/tenant_context\\.py verify ${ctx.replaceAll(".", "\\.")}$`, "m"));
    assert.match(envelope, /attest reports\/tenants\/beta\/hunt-1-01\/context\.json --capability <name> --status <attested\|denied\|unverified> --detail "<non-secret evidence>"/);
    assert.match(envelope, /defender_hunting also needs --via <triage\|graph\|portal>/);
    assert.match(envelope, /readiness reports\/tenants\/beta\/hunt-1-01\/context\.json — query only capabilities listed under "usable"/);
    assert.match(envelope, /2024-01-31T12:00:00Z \.\. 2024-03-01T12:00:00Z/);
    assert.match(envelope, /between \(datetime\(<start>\) \.\. datetime\(<end>\)\) — never ago\(\)/);
    assert.match(envelope, /Statically unsupported for this target[^:]*: triage\./);
    assert.match(envelope, /TRIAGE UNAVAILABLE/);
    assert.match(envelope, /MCP auth remains unverified by the CLI/);
    assert.match(envelope, /B2B guest sign-in or tenant header does NOT prove which tenant an MCP session is authenticated to, and grants no roles/);
    assert.doesNotMatch(envelope, /<captured-/);
    const frozen = JSON.parse(envelope.split("\n")[1]);
    assert.deepEqual(frozen.required_capabilities, ["graph", "tenant_identity"], "only what the CLI can enforce is required");
    assert.deepEqual(Object.keys(frozen.unsupported_capabilities), ["triage"]);
    assert.deepEqual(frozen.window, { start_utc: "2024-01-31T12:00:00Z", end_utc: HUNT_END });
    assert.deepEqual([frozen.hunt_id, frozen.lookback_days], ["hunt-1", 30]);

    const defender = selectContext(registry, "alpha", "", "case-d", { defenderOnly: true });
    const text = launchEnvelope(new LaunchBindings().capture(defender, "ioc-investigation", "s"));
    assert.match(text, /^1\. python scripts\/tenant_context\.py create --profile alpha --no-workspace --case case-d --lookback-days <requested-days> --capability tenant_identity --validate-live$/m);
    assert.match(text, /\(Defender-only\)\. Do not enumerate or query Sentinel workspaces/);
    assert.doesNotMatch(text, /Enumerate available Sentinel workspaces/);
    assert.doesNotMatch(text, /COLLECTION WINDOW/);
    assert.equal(JSON.parse(text.split("\n")[1]).workspace, null);
});

// The commands a hunt target is told to run must be accepted by the real CLI,
// and the ledger that CLI writes must read back identically in the UI view.
test("the frozen create/attest commands are accepted by the Python CLI and its ledger reads back identically",
    { skip: !process.env.MC_TEST_PYTHON && "Set MC_TEST_PYTHON to the configured interpreter to check the Python boundary" }, () => fixture(async root => {
        await writeFile(path.join(root, "config.json"), JSON.stringify(config()));
        const registry = parseRegistry(config());
        const c = selectContext(registry, "alpha", W1, "hunt-1-02", { ...huntOptions, capabilities: ["data_lake", "workspace_query", "defender_hunting"] });
        const envelope = launchEnvelope(new LaunchBindings().capture(c, "cross-tenant-hunt", "s"));
        const line = envelope.split("\n").find(l => l.startsWith("1. python scripts/tenant_context.py create "));
        assert.ok(line, "envelope must contain the frozen create command");
        // Offline: --validate-live needs Azure CLI access to a real tenant.
        const args = line.slice(3).split(" ").slice(3).filter(arg => arg !== "--validate-live");
        const script = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../scripts/tenant_context.py");
        const run = (...rest) => spawnSync(process.env.MC_TEST_PYTHON, [script, "--repo-root", root, ...rest], { encoding: "utf8" });

        const created = run("create", ...args);
        assert.equal(created.status, 0, created.stderr || created.stdout);
        const result = JSON.parse(created.stdout);
        const manifest = JSON.parse(await readFile(result.context_path, "utf8"));
        assert.deepEqual([manifest.schema_version, manifest.hunt_id, manifest.case_id, manifest.lookback_days], [2, "hunt-1", "hunt-1-02", 30]);
        assert.deepEqual(manifest.window, c.window);
        assert.deepEqual(manifest.capabilities, c.capabilities);
        assert.equal(manifest.workspace.id, c.workspace.id);
        assert.equal(await realpath(result.context_path), await realpath(path.join(root, "reports/tenants/alpha/hunt-1-02/context.json")),
            "the context path named in the envelope must be where the CLI writes it");

        const first = run("attest", result.context_path, "--capability", "data_lake", "--status", "attested", "--detail", "operator checked the lake tenant");
        assert.equal(first.status, 0, first.stderr || first.stdout);
        const second = run("attest", result.context_path, "--capability", "defender_hunting", "--status", "attested", "--via", "portal", "--detail", "portal tenant switcher shows Alpha");
        assert.equal(second.status, 0, second.stderr || second.stdout);
        const denied = run("attest", result.context_path, "--capability", "graph", "--status", "denied", "--detail", "guest sign-in refused");
        assert.equal(denied.status, 0, denied.stderr || denied.stdout);

        // Hostile entries the shared JSON fixtures cannot express: both readers must discard them identically.
        const ledger = path.join(path.dirname(result.context_path), "ledger");
        const lake = (await readdir(ledger)).find(name => name.endsWith("-data_lake.json"));
        const [, second_, capability] = /^(\d{8}T\d{6})\d{6}Z-(.+)$/.exec(lake);
        const later = micros => path.join(ledger, `${second_}${micros}Z-${capability}`);
        const body = await readFile(path.join(ledger, lake));
        await writeFile(later("900001"), Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), body]));
        await writeFile(later("900002"), Buffer.concat([body, Buffer.alloc(9000, 0x20)]));
        await writeFile(path.join(ledger, "not-a-ledger-name.json"), body);
        await symlink(path.join(ledger, lake), later("900003"));
        await mkdir(later("900004"));
        spawnSync("mkfifo", [later("900005")]);

        const python = JSON.parse(run("readiness", result.context_path).stdout);
        const advisory = await ledgerReadiness(root, scopeFromManifest(manifest), Date.now());
        for (const key of ["ok", "profile", "tenant_id", "workspace_id", "case_id", "hunt_id", "window", "required", "usable", "blocked", "ignored_records"]) {
            assert.deepEqual(advisory[key], python[key], key);
        }
        assert.deepEqual(advisory.capabilities, python.capabilities);
        assert.ok(advisory.ignored_records >= 5, "hostile entries must be counted as ignored");
        assert.deepEqual(advisory.usable, ["data_lake", "defender_hunting"]);
        assert.equal(advisory.capabilities.data_lake.checked_at, JSON.parse(body).checked_at, "no planted file may shadow the attestation");
        assert.equal(advisory.capabilities.graph.status, "denied");
        assert.deepEqual(advisory.blocked, ["tenant_identity", "workspace_query"]);
    }));

// ── Hunt planning: one request, N independently bound child cases ────────────

const T3 = "33333333-3333-4333-8333-333333333333";
const HUNT_NOW = Date.parse(HUNT_END);
// A guest tenant: no Sentinel workspace and a declared Triage home tenant elsewhere.
const guestConfig = () => {
    const c = config();
    c.tenants.guest = { tenant_id: T3, memory_file: "guest-memory.md", connections: { graph: "guest-graph" }, triage_home_tenant_id: T1 };
    c.tenants.alpha.sit_mapping = { "dddddddd-dddd-4ddd-8ddd-dddddddddddd": "Synthetic SIT never sent to the UI" };
    return c;
};

test("a hunt plan pins one window for every target and gives each its own child case, even inside one tenant", () => {
    const plan = planHunt(parseRegistry(guestConfig()), { huntId: "hunt-1", request: "  Hunt 192.0.2.1  ", lookbackDays: 30,
        targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "alpha", workspaceId: W3 },
            { profile: "beta", workspaceId: W2 }, { profile: "guest", defenderOnly: true }] }, HUNT_NOW);
    assert.deepEqual([plan.mode, plan.huntId, plan.request, plan.lookbackDays], ["launch", "hunt-1", "Hunt 192.0.2.1", 30]);
    assert.deepEqual(plan.window, huntWindow(30, null, HUNT_NOW));
    assert.deepEqual(plan.targets.map(t => t.context.caseId), ["hunt-1-01", "hunt-1-02", "hunt-1-03", "hunt-1-04"]);
    assert.deepEqual(plan.targets.map(t => t.context.workspace?.id ?? null), [W1, W3, W2, null]);
    for (const { context } of plan.targets) {
        assert.deepEqual(context.window, { start_utc: plan.window.start_utc, end_utc: plan.window.end_utc });
        assert.equal(context.huntId, "hunt-1");
    }
    assert.deepEqual(plan.targets.map(t => t.coverage.required),
        [["tenant_identity", "workspace_arm"], ["tenant_identity", "workspace_arm"], ["tenant_identity", "workspace_arm"], ["tenant_identity"]]);
    assert.deepEqual(plan.targets.map(t => t.unavailable), ["", "", "", ""]);
    assert.match(plan.window.end_utc, /^2024-03-01T12:00:00Z$/);
    assert.match(planHunt(parseRegistry(guestConfig()), { request: "x", targets: [{ profile: "alpha", workspaceId: W1 }] }, HUNT_NOW).huntId,
        /^hunt-20240301-[0-9a-f]{6}$/);
    // The legacy single `caseId` field names the hunt.
    const legacy = planHunt(parseRegistry(guestConfig()), { caseId: "case-hunt", request: "x",
        targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "beta", workspaceId: W2 }] }, HUNT_NOW);
    assert.deepEqual(legacy.targets.map(t => t.context.caseId), ["case-hunt-01", "case-hunt-02"]);
});

test("a hunt plan reports capabilities a target can never provide, and a target is unavailable only when nothing requested remains", () => {
    const registry = parseRegistry(guestConfig());
    const targets = [{ profile: "alpha", workspaceId: W1 }, { profile: "beta", workspaceId: W2 }, { profile: "guest", defenderOnly: true }];
    const mixed = planHunt(registry, { huntId: "hunt-2", request: "x", targets, capabilities: ["graph", "triage"] }, HUNT_NOW);
    assert.deepEqual(mixed.targets.map(t => t.coverage.required),
        [["graph", "tenant_identity", "triage"], ["graph", "tenant_identity"], ["graph", "tenant_identity"]]);
    assert.deepEqual(mixed.targets.map(t => t.coverage.unsupported.map(u => u.capability)), [[], ["triage"], ["triage"]]);
    assert.match(mixed.targets[1].coverage.unsupported[0].reason, /home-tenant only/);
    assert.deepEqual(mixed.targets.map(t => t.unavailable), ["", "", ""], "Graph is still requested and available everywhere");

    const onlyTriage = planHunt(registry, { huntId: "hunt-3", request: "x", targets, capabilities: ["triage"] }, HUNT_NOW);
    assert.deepEqual(onlyTriage.targets.map(t => Boolean(t.unavailable)), [false, true, true]);
    assert.match(onlyTriage.targets[1].unavailable, /^No requested capability can be provided for this target: triage \(Triage is home-tenant only/);
});

test("hunt plans reject what cannot be launched safely, naming the target, before anything runs", () => {
    const registry = parseRegistry(guestConfig());
    const ok = { huntId: "hunt-1", request: "x", targets: [{ profile: "alpha", workspaceId: W1 }] };
    const bad = (patch, pattern) => assert.throws(() => planHunt(registry, { ...ok, ...patch }, HUNT_NOW), pattern, JSON.stringify(patch).slice(0, 80));
    bad({ targets: [] }, /1–10/);
    bad({ targets: undefined }, /1–10/);
    bad({ targets: Array.from({ length: MAX_HUNT_TARGETS + 1 }, (_, i) => ({ profile: "alpha", workspaceId: W1, i })) }, /1–10/);
    bad({ request: "   " }, /indicator or hunt request/);
    bad({ request: "x".repeat(12001) }, /12000/);
    bad({ mode: "everything" }, /launch or handoff/);
    bad({ huntId: "Bad Id" }, ContractError);
    for (const lookbackDays of [0, -1, 3651, 1.5, "abc", NaN]) bad({ lookbackDays }, /Lookback must be 1–3650 days/);
    bad({ capabilities: "graph" }, /capabilities must be an array/);
    bad({ capabilities: ["root"] }, /Target 1 \(alpha\): Unknown capability/);
    bad({ targets: [{ profile: "alpha" }] }, /Target 1: each cross-tenant target requires an explicit workspace ID or Defender-only/);
    bad({ targets: [{ profile: "alpha", workspaceId: W2 }] }, /Target 1 \(alpha\): .*does not belong/);
    bad({ targets: [{ profile: "missing", workspaceId: W1 }] }, /Target 1 \(missing\): Unknown/);
    bad({ targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "beta", workspaceId: W2 }, null] }, /Target 3 is invalid/);
    bad({ targets: [{ profile: "guest", defenderOnly: true }], capabilities: ["data_lake"] }, /Target 1 \(guest\): Capabilities require a workspace/);
    bad({ targets: [{ profile: "alpha", workspaceId: W1, defenderOnly: true }] }, /Target 1 \(alpha\): .*Defender-only/);
    bad({ targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "alpha", workspaceId: W1 }] }, /Duplicate hunt target/);
    bad({ targets: [{ profile: "alpha", defenderOnly: true }, { profile: "alpha", defenderOnly: true }] }, /Duplicate hunt target/);
    assert.throws(() => planHunt(parseRegistry({}), ok, HUNT_NOW), /require a tenants registry/);
    // The documented limits are accepted at the boundary.
    assert.equal(planHunt(registry, { ...ok, lookbackDays: 3650 }, HUNT_NOW).lookbackDays, 3650);
    assert.equal(planHunt(registry, { ...ok, lookbackDays: "45" }, HUNT_NOW).lookbackDays, 45);
    assert.equal(planHunt(registry, { ...ok, lookbackDays: null }, HUNT_NOW).lookbackDays, 7);
    // One workspace and Defender-only of the same profile are different targets.
    assert.equal(planHunt(registry, { ...ok, targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "alpha", defenderOnly: true }] }, HUNT_NOW).targets.length, 2);
});

test("hunt prompts carry only the analyst's request, the shared window and the long-window rule", () => {
    const registry = parseRegistry(guestConfig());
    const base = { huntId: "hunt-1", request: "Hunt 192.0.2.1", targets: [{ profile: "alpha", workspaceId: W1 }] };
    const short = huntPrompt(planHunt(registry, { ...base, lookbackDays: 30 }, HUNT_NOW));
    assert.match(short, /\.github\/skills\/cross-tenant-hunt\/SKILL\.md/);
    assert.match(short, /2024-01-31T12:00:00Z \.\. 2024-03-01T12:00:00Z/);
    assert.match(short, /Hunt 192\.0\.2\.1/);
    assert.match(short, /original correlation fields/);
    assert.doesNotMatch(short, /silently truncates/);
    const long = huntPrompt(planHunt(registry, { ...base, lookbackDays: 31 }, HUNT_NOW), { handoff: true });
    assert.match(long, /Advanced Hunting silently truncates to 30 days/);
    assert.doesNotMatch(long, /correlation/);
    assert.match(long, /separate sessions/);
});

test("a hand-off envelope carries the frozen context but no launch token and no canvas actions", () => {
    const plan = planHunt(parseRegistry(guestConfig()), { huntId: "hunt-1", request: "x", lookbackDays: 30, mode: "handoff",
        targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "guest", defenderOnly: true }], capabilities: ["graph"] }, HUNT_NOW);
    const detached = context => ({ correlationId: "", context, skill: "cross-tenant-hunt", sessionId: "", createdAt: HUNT_NOW });
    const [alpha, guest] = plan.targets.map(t => launchEnvelope(detached(t.context), { handoff: true }));
    for (const text of [alpha, guest]) {
        assert.match(text, /^MISSION CONTROL — DETACHED HAND-OFF CONTEXT \(not proof of authentication\)/);
        assert.doesNotMatch(text, /correlationId/);
        assert.doesNotMatch(text, /invoke_canvas_action/);
        assert.match(text, /Do not call record_finding or record_hunt_status/);
        assert.match(text, /If this case's context\.json already exists \(a follow-up in the same case\), skip step 1 and never recreate or overwrite it/);
        assert.match(text, /--lookback-days 30 --hunt-id hunt-1 --window-end 2024-03-01T12:00:00Z --capability graph --capability tenant_identity --validate-live/);
        assert.match(text, /COLLECTION WINDOW \(UTC, identical for every target of hunt hunt-1\): 2024-01-31T12:00:00Z \.\. 2024-03-01T12:00:00Z/);
    }
    assert.match(alpha, new RegExp(`--profile alpha --workspace ${W1} --case hunt-1-01 `));
    assert.match(guest, /--profile guest --no-workspace --case hunt-1-02 /);
    assert.match(guest, /\(Defender-only\)\. Do not enumerate or query Sentinel workspaces/);
    assert.match(guest, /TRIAGE UNAVAILABLE/);
    assert.equal(JSON.parse(guest.split("\n")[1]).workspace, null);
    assert.doesNotMatch(alpha, /guest-memory\.md/);
    assert.match(alpha, /alpha-memory\.md/);
    // The same context launched from Mission Control keeps its token and the action instruction.
    const launched = launchEnvelope(new LaunchBindings().capture(plan.targets[0].context, "cross-tenant-hunt", "s"));
    assert.match(launched, /^MISSION CONTROL — FROZEN LAUNCH CONTEXT/);
    assert.match(launched, /invoke_canvas_action record_finding with ALL these exact correlation fields/);
    assert.match(launched, /"correlationId":"[0-9a-f-]{36}"/);
});

test("reports under a schema-2 case manifest list for their tenant only; ledger records are never listed", () => fixture(async root => {
    const [a] = contexts();
    const dir = path.join(root, "reports", "tenants", "alpha", "hunt-1-01");
    await mkdir(path.join(dir, "ledger"), { recursive: true });
    const manifest = (patch = {}) => JSON.stringify({ schema_version: 2, profile: "alpha", tenant_id: a.tenantId, case_id: "hunt-1-01",
        report_dir: "reports/tenants/alpha/hunt-1-01", hunt_id: "hunt-1", ...patch });
    await writeFile(path.join(dir, "context.json"), manifest());
    await writeFile(path.join(dir, "report.md"), "Synthetic alpha report");
    await writeFile(path.join(dir, "ledger", "20240301T120005000000Z-tenant_identity.json"), "{}");
    const listed = await listReports(root, { tenantKey: "alpha", tenantId: a.tenantId });
    assert.deepEqual(listed.files.map(f => f.path), ["reports/tenants/alpha/hunt-1-01/report.md"]);
    const report = listed.files[0].path;
    assert.equal(await reportMatchesTenant(root, report, "alpha", a.tenantId), true);
    assert.equal(await reportMatchesTenant(root, report, "alpha", T2), false);
    assert.equal(await reportMatchesTenant(root, report, "beta", a.tenantId), false);
    await writeFile(path.join(dir, "context.json"), manifest({ schema_version: 3 }));
    assert.equal(await reportMatchesTenant(root, report, "alpha", a.tenantId), false, "an unknown manifest version fails closed");
    await writeFile(path.join(dir, "context.json"), manifest({ case_id: "hunt-1-02" }));
    assert.equal(await reportMatchesTenant(root, report, "alpha", a.tenantId), false, "a manifest for another case fails closed");
}));

// ── Mission Control API: the production extension with only the SDK stubbed ──

// A record the writer would produce, minutes old, so the advisory view (which uses the real clock) accepts it.
const freshRecord = (scope, patch = {}) => {
    const stamp = ms => new Date(ms).toISOString().slice(0, 19) + "Z";
    return sampleRecord(scope, { checked_at: stamp(Date.now() - 60_000), expires_at: stamp(Date.now() + 86_400_000), ...patch });
};

test("HTTP hunts: pinned window, child cases, Defender-only guests, hand-off, unavailable targets and advisory readiness",
    { skip: !vm.SourceTextModule && "Run with --experimental-vm-modules for SDK-boundary integration" }, () => fixture(async root => {
        await writeFile(path.join(root, "config.json"), JSON.stringify(guestConfig()));
        await mkdir(path.join(root, ".github", "manifests"), { recursive: true });
        await writeFile(path.join(root, ".github", "manifests", "discovery-manifest.yaml"),
            'skills:\n- name: ioc-investigation\n  prompt: Investigate {entity}\n  domains:\n  - identity\nqueries:\n');
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
            const scope = JSON.parse(/const MC_SCOPE = (.*);/.exec(html)[1]);
            revision = scope.revision;
            assert.deepEqual(scope.profiles.map(p => p.key), ["alpha", "beta", "guest"]);
            assert.doesNotMatch(html, /Synthetic SIT never sent to the UI/);
            assert.equal(scope.profiles.some(p => "mappings" in p), false);
            assert.deepEqual(scope.capabilities.map(c => c.name), Object.keys(CAPABILITIES));
            assert.deepEqual(scope.capabilities.map(c => c.name === "tenant_identity" ? "id" : c.proof), ["id", "cli", "cli", "attested", "attested", "attested", "attested"]);
            assert.equal(scope.profiles.find(p => p.key === "guest").workspaces.length, 0);

            // A guest tenant with no workspace is selectable as Defender-only, and never by accident.
            const guest = await request("/api/context", { profile: "guest", workspaceId: "", defenderOnly: true, caseId: "case-guest" });
            assert.equal(guest.data.ok, true);
            assert.equal(guest.data.context.selected.defenderOnly, true);
            assert.equal(guest.data.context.selected.workspace, null);
            revision = guest.data.context.revision;
            assert.equal(app.sent.length, 0, "selecting a context must not query or authenticate");
            const alphaDefender = await request("/api/context", { profile: "alpha", workspaceId: W1, defenderOnly: true });
            assert.equal(alphaDefender.code, 400, "a workspace and Defender-only together are contradictory");
            assert.equal(alphaDefender.data.context, undefined);

            // Validation failures reject the whole request: nothing is sent, queued or recorded.
            const wrongRequests = [
                { targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "beta", workspaceId: W1 }], request: "x" },
                { targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "guest", defenderOnly: true }], request: "x", capabilities: ["data_lake"] },
                { targets: [{ profile: "alpha", workspaceId: W1 }], request: "x", lookbackDays: 3651 },
                { targets: [{ profile: "alpha", workspaceId: W1 }], request: "x", mode: "everything" },
            ];
            for (const body of wrongRequests) assert.equal((await request("/api/cross-tenant-hunt", body)).code, 500, JSON.stringify(body));
            assert.equal(app.sent.length, 0);
            assert.deepEqual((await request("/api/hunts")).data.hunts, []);

            // Launch: one request, three independently bound child cases and one pinned window.
            const launch = await request("/api/cross-tenant-hunt", { huntId: "hunt-http-1", request: "Hunt 192.0.2.1", lookbackDays: 45,
                capabilities: ["graph", "triage"], targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "alpha", workspaceId: W3 },
                    { profile: "guest", defenderOnly: true }] });
            assert.equal(launch.code, 200);
            assert.equal(launch.data.mode, "launch");
            assert.equal(launch.data.huntId, "hunt-http-1");
            assert.equal(launch.data.ok, true);
            assert.deepEqual(launch.data.results.map(r => [r.profile, r.workspaceId, r.defenderOnly, r.caseId, r.huntId]),
                [["alpha", W1, false, "hunt-http-1-01", "hunt-http-1"], ["alpha", W3, false, "hunt-http-1-02", "hunt-http-1"],
                    ["guest", "", true, "hunt-http-1-03", "hunt-http-1"]]);
            assert.deepEqual(launch.data.results.map(r => r.status), ["sent", "queued", "queued"]);
            for (const r of launch.data.results) assert.deepEqual(r.window, { start_utc: launch.data.window.start_utc, end_utc: launch.data.window.end_utc });
            assert.equal(launch.data.window.lookback_days, 45);
            assert.deepEqual(launch.data.results.map(r => r.requiredCapabilities),
                [["graph", "tenant_identity", "triage"], ["graph", "tenant_identity", "triage"], ["graph", "tenant_identity"]]);
            assert.deepEqual(launch.data.results.map(r => r.unsupportedCapabilities.map(u => u.capability)), [[], [], ["triage"]]);
            assert.equal(new Set(launch.data.results.map(r => r.binding.correlationId)).size, 3);
            assert.equal(app.sent.length, 1, "the executor runs one frozen target at a time");
            const first = app.sent[0].prompt;
            assert.match(first, new RegExp(`--profile alpha --workspace ${W1} --case hunt-http-1-01 --lookback-days 45 --hunt-id hunt-http-1 --window-end ${launch.data.window.end_utc} `));
            assert.match(first, new RegExp(`${launch.data.window.start_utc} \\.\\. ${launch.data.window.end_utc}`));
            assert.match(first, /alpha-memory\.md/);
            assert.doesNotMatch(first, /beta-memory\.md|guest-memory\.md/);
            assert.match(first, /exceeds 30 days/);

            // Advisory evidence: a bound case reads back what the CLI wrote, never more.
            const [one, , three] = launch.data.results;
            const alphaScope = { profile: "alpha", tenantId: T1, caseId: "hunt-http-1-01" };
            const identity = freshRecord(alphaScope);
            await seedLedger(root, alphaScope, { [ledgerName(identity)]: identity });
            const readiness = await request("/api/readiness", { bindings: [one.binding, { ...three.binding, correlationId: "forged" }] });
            assert.equal(readiness.code, 200);
            const [own, forged] = readiness.data.readiness;
            assert.equal(own.readiness.advisory, true);
            assert.deepEqual(own.readiness.usable, ["tenant_identity"]);
            assert.deepEqual(own.readiness.blocked, ["graph", "triage"]);
            assert.match(own.readiness.authoritative_command, /tenant_context\.py readiness <context-path>$/);
            assert.equal(forged.error !== undefined, true, "a forged launch binding is refused");
            assert.equal(forged.readiness, undefined);
            const evidence = await request("/api/readiness", { targets: [{ profile: "alpha", workspaceId: W3 }, { profile: "beta", workspaceId: W2 },
                { profile: "guest", defenderOnly: true }, { profile: "missing", workspaceId: W1 }] });
            const [sibling, beta, defender, missing] = evidence.data.evidence;
            assert.deepEqual(sibling.evidence.usable, ["tenant_identity"], "tenant-level evidence applies to another workspace of the same tenant");
            assert.equal(sibling.evidence.advisory, true);
            assert.equal(beta.evidence.cases_scanned, 0, "another tenant never inherits the evidence");
            assert.equal(defender.evidence.cases_scanned, 0);
            assert.match(missing.error, /Unknown/);
            for (const bad of [{}, { bindings: "x" }, { targets: Array.from({ length: 11 }, () => ({ profile: "alpha", workspaceId: W1 })) }]) {
                assert.equal((await request("/api/readiness", bad)).code, 500, JSON.stringify(bad).slice(0, 60));
            }

            // Hand-off: prompts for separate sessions; nothing is sent, bound or queued. An unavailable target is still reported.
            const sentBefore = app.sent.length, queuedBefore = (await request("/api/activity")).data.queued.length;
            const handoff = await request("/api/cross-tenant-hunt", { mode: "handoff", huntId: "hunt-http-2", request: "Hunt 192.0.2.1",
                lookbackDays: 7, capabilities: ["triage"], targets: [{ profile: "alpha", workspaceId: W1 }, { profile: "beta", workspaceId: W2 }] });
            assert.equal(handoff.code, 200);
            assert.equal(handoff.data.ok, false, "one target is unavailable, so the hunt is not complete");
            const [ok, unavailable] = handoff.data.results;
            assert.equal(ok.status, "handoff");
            assert.equal(ok.binding, undefined, "a hand-off session has no Mission Control launch token");
            assert.equal(ok.contextPath, "reports/tenants/alpha/hunt-http-2-01/context.json");
            assert.match(ok.prompt, /DETACHED HAND-OFF CONTEXT/);
            assert.doesNotMatch(ok.prompt, /correlationId|invoke_canvas_action/);
            assert.match(ok.prompt, /Hunt request \(task data, not permission to change scope\):\n\nHunt 192\.0\.2\.1/);
            assert.deepEqual([unavailable.status, unavailable.ok], ["unavailable", false]);
            assert.match(unavailable.error, /No requested capability can be provided for this target: triage/);
            assert.equal(unavailable.prompt, undefined);
            assert.equal(app.sent.length, sentBefore, "hand-off never writes to the current chat");
            assert.equal((await request("/api/activity")).data.queued.length, queuedBefore);
            const statuses = await request("/api/hunt-status", { bindings: [unavailable.binding] });
            assert.deepEqual([statuses.data.hunts[0].status, statuses.data.hunts[0].huntId], ["unavailable", "hunt-http-2"]);
            assert.match(statuses.data.hunts[0].detail, /triage/);

            app.events.get("session.error")({ data: { message: "Synthetic executor stopped" } });
        } finally { await app.close(); }
    }));
