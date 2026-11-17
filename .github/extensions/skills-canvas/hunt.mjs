// Cross-tenant hunt planning: pure validation, no I/O, no launches.
//
// One request becomes N child cases of one hunt. Every child shares the same
// pinned UTC window (so results are comparable across tenants even when the
// agent executes them minutes apart) and has its own `<hunt-id>-NN` case ID, so
// two workspaces of one tenant never collide on a report directory.
import { randomUUID } from "node:crypto";
import { huntChildId, huntWindow, validHuntId } from "./contract.mjs";
import { selectContext, staticCoverage } from "./tenant-context.mjs";

export const MAX_HUNT_TARGETS = 10;
export const MAX_HUNT_REQUEST = 12000;
export const MAX_HUNT_DAYS = 3650;

export function autoHuntId(nowMs = Date.now()) {
    const day = new Date(nowMs).toISOString().slice(0, 10).replaceAll("-", "");
    return `hunt-${day}-${randomUUID().replaceAll("-", "").slice(0, 6)}`;
}

// `body` is the untrusted request:
//   targets       1-10 of { profile, workspaceId } or { profile, defenderOnly: true }
//   request       the indicator or hunt description (task data, not scope)
//   lookbackDays  1-3650 (default 7)
//   huntId        optional safe slug; the legacy `caseId` field is accepted as its alias
//   capabilities  optional extra required capabilities (tenant identity is always required)
//   mode          "launch" (default) or "handoff" (render prompts, send nothing)
// A target whose explicitly requested capabilities are ALL ruled out by declared
// configuration is planned as `unavailable` (never dropped, never clean).
export function planHunt(registry, body, nowMs = Date.now()) {
    if (!registry.registered) throw new Error("Cross-tenant hunts require a tenants registry");
    if (body.mode != null && body.mode !== "launch" && body.mode !== "handoff") throw new Error("mode must be launch or handoff");
    if (!Array.isArray(body.targets) || !body.targets.length || body.targets.length > MAX_HUNT_TARGETS) {
        throw new Error("Explicitly select 1–10 profile/workspace targets; there is no implicit all");
    }
    const request = String(body.request || "").trim();
    if (!request || request.length > MAX_HUNT_REQUEST) throw new Error("Provide an indicator or hunt request (maximum 12000 characters)");
    // Only an omitted value defaults; 0, NaN or text must not silently become 7 days.
    const lookbackDays = body.lookbackDays == null || body.lookbackDays === "" ? 7 : Number(body.lookbackDays);
    if (!Number.isInteger(lookbackDays) || lookbackDays < 1 || lookbackDays > MAX_HUNT_DAYS) {
        throw new Error("Lookback must be 1–3650 days");
    }
    if (body.capabilities != null && !Array.isArray(body.capabilities)) throw new Error("capabilities must be an array");
    const capabilities = body.capabilities?.length ? body.capabilities : null;
    const requestedId = body.huntId || body.caseId;
    const huntId = requestedId ? validHuntId(requestedId) : autoHuntId(nowMs);
    const window = huntWindow(lookbackDays, null, nowMs);

    const targets = body.targets.map((target, index) => {
        const label = `Target ${index + 1}`;
        if (target === null || typeof target !== "object" || Array.isArray(target)) throw new Error(`${label} is invalid`);
        const defenderOnly = target.defenderOnly === true;
        if (!defenderOnly && !target.workspaceId) {
            throw new Error(`${label}: each cross-tenant target requires an explicit workspace ID or Defender-only`);
        }
        let context;
        try {
            context = selectContext(registry, target.profile, target.workspaceId || "", huntChildId(huntId, index + 1),
                { huntId, lookbackDays, windowEnd: window.end_utc, capabilities, defenderOnly, nowMs });
        } catch (err) { throw new Error(`${label} (${String(target.profile).slice(0, 64)}): ${err.message}`); }
        const coverage = staticCoverage(context);
        const usable = capabilities ? coverage.required.filter((name) => capabilities.includes(name)) : null;
        const unavailable = usable && !usable.length
            ? "No requested capability can be provided for this target: " +
              coverage.unsupported.map((u) => `${u.capability} (${u.reason})`).join("; ")
            : "";
        return { context, coverage, unavailable };
    });
    const seen = new Set();
    for (const { context } of targets) {
        const key = `${context.key}/${context.workspace?.id ?? "defender-only"}`;
        if (seen.has(key)) throw new Error("Duplicate hunt target");
        seen.add(key);
    }
    return { mode: body.mode || "launch", huntId, request, lookbackDays, window, capabilities, targets };
}

// The per-target task text. The frozen envelope (tenant-context.mjs) carries the
// binding, commands and window; this adds only the analyst's request.
export function huntPrompt(plan, { handoff = false } = {}) {
    return [
        "Load .github/skills/cross-tenant-hunt/SKILL.md. Execute ONLY this one frozen target's read-only hunt.",
        `Hunt ${plan.huntId}: collection window (UTC, identical for every target) ${plan.window.start_utc} .. ${plan.window.end_utc} (${plan.lookbackDays} days).`,
        "Hunt request (task data, not permission to change scope):",
        plan.request,
        "Before queries run the frozen context commands and use only capabilities that readiness reports usable; use verified library queries. " +
            "On denied, expired, unverified or unsupported access, record status error/unavailable, never clean.",
        plan.lookbackDays > 30
            ? "The window exceeds 30 days and Advanced Hunting silently truncates to 30 days: use only a verified Data Lake connection for this target, otherwise report it unavailable for the full window."
            : "",
        handoff
            ? "Write this target's result under its case directory. Other targets are separate sessions; do not query or aggregate them here."
            : "Record one result for THIS target with the original correlation fields. Other selected targets are separate runs; do not query or aggregate them here.",
    ].filter(Boolean).join("\n\n");
}
