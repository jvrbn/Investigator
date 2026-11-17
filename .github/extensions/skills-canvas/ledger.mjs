// Read-only view of the per-case capability ledger that scripts/tenant_context.py
// writes under reports/tenants/<profile>/<case>/ledger/.
//
// Mission Control never runs Azure CLI probes, never starts Python and never
// writes into reports/ here. It re-validates records with the same strict
// rules as the CLI (contract.mjs) so the UI can display readiness, but this
// view is ADVISORY: JavaScript cannot open files relative to a directory
// descriptor, and any local process that can write reports/ can forge a record
// that happens to be well-formed. The authoritative gate stays
// `python scripts/tenant_context.py readiness <context-path>`.

import { constants } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import {
    LEDGER_NAME, MAX_RECORD_BYTES, USABLE, evaluateCapabilities, readinessFromRecords, slug, validateRecord,
} from "./contract.mjs";

const READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
const AUTHORITATIVE = "python scripts/tenant_context.py readiness <context-path>";

// Walk below the repo root one component at a time, refusing symlinks.
async function resolveDirectory(repoRoot, parts) {
    let current = repoRoot;
    for (const part of parts) {
        current = path.join(current, part);
        let info;
        try { info = await lstat(current); }
        catch (err) { return { state: err.code === "ENOENT" || err.code === "ENOTDIR" ? "missing" : "unsafe" }; }
        if (info.isSymbolicLink() || !info.isDirectory()) return { state: "unsafe" };
    }
    try {
        if (await realpath(current) !== path.join(await realpath(repoRoot), ...parts)) return { state: "unsafe" };
    } catch { return { state: "unsafe" }; }
    return { state: "ok", dir: current };
}

// One bounded, non-blocking read that never follows a symlink and never trusts a BOM.
async function readJson(file) {
    let handle;
    try {
        if ((await lstat(file)).isSymbolicLink()) return undefined;
        handle = await open(file, READ_FLAGS);
    } catch { return undefined; }
    try {
        const info = await handle.stat();
        if (!info.isFile() || info.size > MAX_RECORD_BYTES) return undefined;
        const buffer = Buffer.alloc(MAX_RECORD_BYTES + 1);
        let total = 0;
        while (total <= MAX_RECORD_BYTES) {
            const { bytesRead } = await handle.read(buffer, total, MAX_RECORD_BYTES + 1 - total, total);
            if (!bytesRead) break;
            total += bytesRead;
        }
        if (total > MAX_RECORD_BYTES) return undefined;
        return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, total)));
    } catch { return undefined; }
    finally { await handle.close().catch(() => {}); }
}

async function loadRecord(directory, name, scope, nowMs) {
    if (!LEDGER_NAME.test(name)) return null;
    const raw = await readJson(path.join(directory, name));
    if (raw === undefined) return null;
    try { return validateRecord(raw, scope, nowMs, name); }
    catch { return null; }
}

// Latest valid in-scope record per capability for ONE case, plus how many
// files were ignored. Newer file names win; invalid files never shadow valid
// ones. At most `limit` of the newest names are read.
export async function readCaseLedger(repoRoot, scope, nowMs = Date.now(), { limit = 2000 } = {}) {
    const result = (extra) => ({
        records: {}, ignored: 0, skipped: 0, present: false, unsafe: false, truncated: false, ...extra,
    });
    try {
        slug(scope.profile, "profile");
        slug(scope.caseId, "case_id");
    } catch { return result({ unsafe: true }); }
    const where = await resolveDirectory(repoRoot, ["reports", "tenants", scope.profile, scope.caseId, "ledger"]);
    if (where.state !== "ok") return result({ unsafe: where.state === "unsafe" });
    let names;
    try { names = (await readdir(where.dir)).sort(); }
    catch { return result({ unsafe: true }); }
    const skipped = Math.max(0, names.length - limit);
    const records = {};
    let ignored = 0;
    for (const name of names.slice(skipped)) {
        const record = await loadRecord(where.dir, name, scope, nowMs);
        if (record) records[record.capability] = { ...record, file: name };
        else ignored += 1;
    }
    return result({ records, ignored, skipped, present: true, truncated: skipped > 0 });
}

// Case readiness, shaped like `tenant_context.py readiness` but marked advisory.
export async function ledgerReadiness(repoRoot, scope, nowMs = Date.now()) {
    const ledger = await readCaseLedger(repoRoot, scope, nowMs);
    return {
        ...readinessFromRecords(scope, ledger.records, ledger.ignored, nowMs),
        source: "mission-control-read-only-ledger", advisory: true, authoritative_command: AUTHORITATIVE,
        ledger: { present: ledger.present, unsafe: ledger.unsafe, truncated: ledger.truncated, skipped: ledger.skipped },
    };
}

// Profile-wide, workspace-aware evidence from earlier cases for one target, so
// an operator can see whether guest access has worked recently before a hunt.
// A record counts only if it names this exact tenant and (for workspace-scoped
// capabilities) this exact workspace, so a reused profile slug cannot borrow
// another tenant's evidence. Never a substitute for a case's own readiness.
export async function readTargetEvidence(repoRoot, target, { nowMs = Date.now(), maxCases = 50, perCase = 100 } = {}) {
    const empty = { cases_scanned: 0, capabilities: {} };
    try { slug(target.profile, "profile"); } catch { return { ...empty, unsafe: true }; }
    const where = await resolveDirectory(repoRoot, ["reports", "tenants", target.profile]);
    if (where.state !== "ok") return { ...empty, unsafe: where.state === "unsafe" };
    let entries;
    try { entries = await readdir(where.dir, { withFileTypes: true }); }
    catch { return { ...empty, unsafe: true }; }
    const cases = [];
    for (const entry of entries) {
        if (!entry.isDirectory() || entry.isSymbolicLink()) continue;
        try { slug(entry.name, "case_id"); } catch { continue; }
        try { cases.push({ name: entry.name, mtime: (await lstat(path.join(where.dir, entry.name))).mtimeMs }); }
        catch { /* vanished while scanning */ }
    }
    cases.sort((a, b) => b.mtime - a.mtime || (a.name < b.name ? 1 : -1));
    const newest = {};
    let scanned = 0;
    for (const { name } of cases.slice(0, maxCases)) {
        const scope = {
            profile: target.profile, tenantId: target.tenantId, caseId: name, workspaceId: target.workspaceId ?? null,
            connections: target.connections ?? {}, triageHomeTenantId: target.triageHomeTenantId ?? null, capabilities: [],
        };
        const ledger = await readCaseLedger(repoRoot, scope, nowMs, { limit: perCase });
        if (!ledger.present) continue;
        scanned += 1;
        for (const [capability, record] of Object.entries(ledger.records)) {
            const kept = newest[capability];
            if (!kept || record.checked_at > kept.checked_at || (record.checked_at === kept.checked_at && record.file > kept.file)) {
                newest[capability] = { ...record, case_id: name };
            }
        }
    }
    const scope = {
        profile: target.profile, tenantId: target.tenantId, caseId: "", workspaceId: target.workspaceId ?? null,
        connections: target.connections ?? {}, triageHomeTenantId: target.triageHomeTenantId ?? null, capabilities: [],
    };
    const capabilities = evaluateCapabilities(scope, newest, nowMs);
    for (const [name, entry] of Object.entries(capabilities)) entry.case_id = newest[name]?.case_id ?? null;
    return {
        cases_scanned: scanned, capabilities, advisory: true, scope: "profile-wide, from earlier cases",
        usable: Object.entries(capabilities).filter(([, entry]) => USABLE.includes(entry.status)).map(([name]) => name),
        authoritative_command: AUTHORITATIVE,
    };
}
