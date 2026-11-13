// Directory listing for the Mission Control Reports tab. The canvas already
// knows how to *render* a report — `/api/report` serves any repo file and
// md.mjs turns markdown into the dark-themed preview page. What was missing is
// a way to *browse* reports/, so this module does one job: walk that tree and
// hand the client a flat, sorted file list it can present as either a folder
// tree or a "most recent first" list.
//
// Everything here is best-effort. A missing reports/ directory, an unreadable
// subfolder or a vanished file yields a smaller list, never an exception —
// the tab should degrade to "no reports" rather than break the canvas.

import { readdir, stat, realpath, readFile } from "node:fs/promises";
import path from "node:path";
import { safeSlug } from "./tenant-context.mjs";

// Extensions the preview iframe can actually display. serveReport() gives
// markdown the rendered page, and hands SVG/HTML to the browser with a real
// content type; anything else would download rather than preview, so it is
// left out of the listing entirely.
const VIEWABLE = new Set([".md", ".markdown", ".svg", ".html", ".htm"]);

// Coarse type tag used by the client's type filter, so the UI never has to
// re-derive a grouping from raw extensions.
function kindOf(ext) {
    if (ext === ".md" || ext === ".markdown") return "md";
    if (ext === ".svg") return "svg";
    return "html";
}

const ROOT_DIR = "reports";
const MAX_DEPTH = 8; // deep enough for reports/<skill>/<sub>/…, shallow enough to bound a runaway tree

// Scans are cheap (a few hundred files) but the tab re-enters often — switching
// away and back should not re-walk the tree. The ⟳ button passes refresh=true
// so a report written seconds ago still shows up on demand.
const CACHE_TTL_MS = 5000;
let cache = null;
let cacheKey = "";

// Slugs can be reassigned to another customer. A directory name alone is not
// enough: a scoped preview must match the canonical case's recorded tenant.
export async function reportMatchesTenant(repoRoot, rel, tenantKey, tenantId) {
    try {
        safeSlug(tenantKey);
        const parts = rel.split("/");
        if (parts.length < 5 || parts[0] !== "reports" || parts[1] !== "tenants" || parts[2] !== tenantKey ||
            parts.some(p => !p || p === "." || p === ".." || p.includes("\\"))) return false;
        safeSlug(parts[3]);
        const caseDir = path.join(repoRoot, ...parts.slice(0, 4));
        if (await realpath(caseDir) !== caseDir) return false;
        const manifest = path.join(caseDir, "context.json");
        if (await realpath(manifest) !== manifest) return false;
        const c = JSON.parse(await readFile(manifest, "utf8"));
        return c.schema_version === 1 && c.profile === tenantKey && c.tenant_id === tenantId &&
            c.case_id === parts[3] && c.report_dir === parts.slice(0, 4).join("/");
    } catch { return false; }
}

/**
 * Recursively collect viewable report files under `dir`.
 *
 * `rel` is the repo-relative prefix for the current directory, carried down so
 * every emitted path is already in the form `/api/report?path=` expects.
 * Uses withFileTypes so symlinks are visible as such and can be skipped —
 * following them could walk outside reports/ (and potentially outside the repo
 * that serveReport is careful to stay inside).
 */
async function walk(dir, rel, depth, out) {
    if (depth > MAX_DEPTH) return;
    let entries;
    try {
        entries = await readdir(dir, { withFileTypes: true });
    } catch {
        return; // unreadable subtree — skip it rather than failing the whole scan
    }
    for (const entry of entries) {
        const name = entry.name;
        if (name.startsWith(".")) continue; // .gitkeep and friends are not reports
        if (entry.isSymbolicLink()) continue;
        const abs = path.join(dir, name);
        const relPath = rel ? rel + "/" + name : name;
        if (entry.isDirectory()) {
            await walk(abs, relPath, depth + 1, out);
            continue;
        }
        if (!entry.isFile()) continue;
        const ext = path.extname(name).toLowerCase();
        if (!VIEWABLE.has(ext)) continue;
        let info;
        try {
            info = await stat(abs);
        } catch {
            continue; // deleted between readdir and stat
        }
        out.push({
            // Repo-relative (e.g. reports/<folder>/<file>.md) so it drops straight
            // into /api/report?path=, which resolves against the repo root.
            path: ROOT_DIR + "/" + relPath,
            name,
            // Relative to reports/ instead ("" for files sitting directly under it),
            // because that is what the client groups the folder tree by.
            dir: rel,
            ext,
            kind: kindOf(ext),
            size: info.size,
            mtime: info.mtimeMs,
        });
    }
}

/**
 * List every viewable file under `<repoRoot>/reports`.
 *
 * Returns `{ files, dirs, total, scannedAt }`:
 *  - `files` newest first, so the client's "Recent" mode needs no re-sort and
 *    the tree gets newest-first ordering within each folder for free. Each
 *    file's `path` is repo-relative (`reports/…`) for `/api/report`, while its
 *    `dir` is relative to `reports/` for tree grouping.
 *  - `dirs` is every directory that holds at least one file, plus its ancestors,
 *    sorted alphabetically — relative to `reports/`, matching each file's `dir`.
 *
 * Never throws; a missing reports/ directory returns an empty payload.
 */
export async function listReports(repoRoot, { refresh = false, tenantKey = "", tenantId = "" } = {}) {
    if (tenantKey) safeSlug(tenantKey);
    const key = repoRoot + "|" + tenantKey + "|" + tenantId;
    if (!refresh && cacheKey === key && cache && Date.now() - cache.scannedAt < CACHE_TTL_MS) return cache;

    const prefix = tenantKey ? "tenants/" + tenantKey : "";
    const root = path.join(repoRoot, ROOT_DIR, prefix);
    const files = [];
    const canonical = await realpath(root).catch(() => "");
    const repo = await realpath(repoRoot);
    if (canonical && canonical.startsWith(repo + path.sep) && (!tenantKey || canonical === path.join(repo, ROOT_DIR, prefix))) {
        await walk(root, prefix, 0, files);
    }
    if (tenantKey) {
        const matches = await Promise.all(files.map(f => reportMatchesTenant(repoRoot, f.path, tenantKey, tenantId)));
        for (let i = files.length - 1; i >= 0; i--) if (!matches[i]) files.splice(i, 1);
    }
    files.sort((a, b) => b.mtime - a.mtime);

    // Expand each file's directory into its full ancestor chain, so a folder
    // that only contains subfolders still appears as a collapsible tree node.
    const dirSet = new Set();
    for (const f of files) {
        if (!f.dir) continue;
        const parts = f.dir.split("/");
        for (let i = 1; i <= parts.length; i++) dirSet.add(parts.slice(0, i).join("/"));
    }

    cacheKey = key;
    cache = {
        files,
        dirs: [...dirSet].sort(),
        total: files.length,
        scannedAt: Date.now(),
    };
    return cache;
}
