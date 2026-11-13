# Reusable plan: configure MCP tenant selection

## Goal

Reproduce the changes made in the original project:

1. Add `x-mcp-client-tenant-id` to exactly three HTTP servers in `.vscode\mcp.json`.
2. Add multi-tenant setup and limitation guidance to the root `README.md`.

Leave `config.json`, all other servers, and all existing server settings unchanged. Do not add dependencies, provision tenant applications, change permissions, or modify global VS Code settings.

The only value to substitute is `<TARGET_TENANT_ID>`, taken from the destination project's existing `config.json` field `tenant_id`. Do not copy the original project's tenant ID into a different environment.

## 1. Inspect the destination project

- Read the project's applicable instructions.
- Locate `.vscode\mcp.json`, `config.json`, and the MCP setup section of `README.md`.
- Run `git --no-pager status --short` from the project root to identify existing changes.
- Confirm that the following server entries exist:
  - `sentinel-data-mcp`
  - `sentinel-triage-mcp`
  - `Graph-mcp-server`
- Check whether any of these servers already has headers. Preserve unrelated headers; replace only an existing `x-mcp-client-tenant-id` if necessary.
- Capture a local, temporary baseline of the parsed environment and MCP configurations for preservation checks. Do not commit it or expose API tokens.

The original MCP file is JSON with comments (JSONC). Preserve those comments and the existing formatting.

## 2. Select the tenant

- Read `tenant_id` from `config.json`.
- Validate that it is a canonical Entra ID tenant GUID.
- Confirm that `azure_mcp.tenant`, when present, is consistent with that tenant.
- Use the same tenant GUID for all three headers.
- Do not use a subscription ID or Sentinel workspace ID.
- Do not restructure or rewrite `config.json`.

This follows the original change's assumption that the existing environment configuration identifies the intended target tenant. If it actually identifies the home tenant rather than the delegated/customer tenant, obtain the correct target GUID before applying the headers.

## 3. Apply the MCP configuration change

Merge the following properties into the existing server entries. This is a reference excerpt, not a replacement for the entire `servers` object:

```json
{
  "sentinel-data-mcp": {
    "type": "http",
    "url": "https://sentinel.microsoft.com/mcp/data-exploration",
    "headers": {
      "x-mcp-client-tenant-id": "<TARGET_TENANT_ID>"
    }
  },
  "Graph-mcp-server": {
    "type": "http",
    "url": "https://mcp.svc.cloud.microsoft/enterprise",
    "headers": {
      "x-mcp-client-tenant-id": "<TARGET_TENANT_ID>"
    }
  },
  "sentinel-triage-mcp": {
    "type": "http",
    "url": "https://sentinel.microsoft.com/mcp/triage",
    "headers": {
      "x-mcp-client-tenant-id": "<TARGET_TENANT_ID>"
    }
  }
}
```

For each entry, add a comma after the existing `url` property and add `headers` alongside `type` and `url`.

Preserve:

- All server URLs and transport types.
- All other properties and headers.
- The complete `inputs` array.
- All commands, arguments, and environment variables.
- Every server outside the three named entries, including `sentinel-graph-mcp` and local MCP Apps.

Do not put this header in `config.json`; that file does not automatically configure MCP authentication.

## 4. Apply the README change

In the MCP configuration setup section, insert the following block after the first-use authentication prompts and before the per-server setup reference. This is the same documentation block added in the original project:

````markdown
**Multi-tenant (optional):** To select a specific tenant, add the following property alongside `type` and `url` in each `sentinel-data-mcp`, `sentinel-triage-mcp`, and `Graph-mcp-server` entry in [.vscode/mcp.json](.vscode/mcp.json):

```json
"headers": {
  "x-mcp-client-tenant-id": "<your-tenant-id>"
}
```

Use the target Entra ID Directory (tenant) GUID, not a subscription or workspace ID. Keep it consistent with `tenant_id` and `azure_mcp.tenant` in [config.json](config.json); those environment settings do not automatically configure MCP authentication. Without the header, sign-in defaults to your account's home tenant.

After changing the headers, use **MCP: List Servers** in the VS Code Command Palette to restart the affected servers and sign in again if prompted. If an existing authentication session still targets the wrong tenant, sign out of that MCP connection and reconnect. The target tenant still requires the appropriate roles and Microsoft Graph provisioning/consent.

> **Sentinel triage limitation:** Microsoft's [triage documentation](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool#limitations) states that guest and delegated access aren't supported; the triage collection can only be used in your account's home tenant. Adding the header does not remove this limitation. Use an account whose home tenant is the target tenant for triage.
````

Keep tenant-specific values out of the README and the shared MCP template. The original change did not modify `.vscode\mcp.json.template`.

## 5. Validate the changes

Use the same configuration-validation approach as the original change:

1. Parse `config.json` as strict JSON.
2. Parse `.vscode\mcp.json` as JSONC. With PowerShell 7 and `System.Text.Json.JsonDocument`, use `CommentHandling = Skip` and `AllowTrailingCommas = true`.
3. Confirm that each of the three target servers remains an HTTP server and has the exact header:
   - Name: `x-mcp-client-tenant-id`
   - Value: the selected tenant GUID, as a string
4. Compare the parsed MCP configuration with the baseline plus only the expected header changes. All other settings must be unchanged.
5. Compare the parsed environment configuration with its baseline. `config.json` must be unchanged.
6. Run `git --no-pager status --short` again and confirm that unrelated work was not modified.
7. Confirm that local configuration files remain gitignored if the destination project already follows that convention. Do not change its ignore rules as part of this plan.

No dependency installation, application build, or unit-test run was needed for the original configuration/documentation-only change.

## 6. Activate and report accurately

1. Open the destination project as a VS Code workspace folder so its `.vscode\mcp.json` is loaded.
2. Run **MCP: List Servers** and restart the three affected connections.
3. Authenticate with an account authorized in the target tenant.
4. If a cached session still uses the wrong tenant, sign out of that MCP connection and reconnect.

Tenant selection does not grant Azure roles, Microsoft Graph consent, or application provisioning.

The original change verified configuration syntax and preservation, but did not verify a newly authenticated MCP session. Keep those outcomes separate when reporting completion.

Guest/delegated Sentinel triage access is a documented platform limitation, not a configuration problem that this header solves. Do not claim all three servers support delegated access.

## 7. Finish

- Remove task-specific temporary baselines and downloaded documentation files.
- Report the selected tenant, the three changed server entries, the README update, and validation results.
- State whether authenticated access was actually tested.
- Do not commit changes unless separately requested.

## Acceptance criteria

- The three specified servers have the correct tenant header.
- Every other MCP setting is preserved.
- `config.json` is unchanged.
- Configuration syntax validation passes.
- The README contains the setup, reconnect, permissions, and triage limitation guidance.
- No unrelated files, dependencies, or global settings were changed.

## Official references used for the original change

- [Sentinel MCP troubleshooting: guest authentication and tenant headers](https://learn.microsoft.com/en-us/azure/sentinel/datalake/troubleshoot-sentinel-mcp#troubleshooting)
- [Sentinel triage limitations](https://learn.microsoft.com/en-us/azure/sentinel/datalake/sentinel-mcp-triage-tool#limitations)
- [Microsoft Graph / Enterprise MCP provisioning and setup](https://learn.microsoft.com/en-us/graph/mcp-server/get-started?tabs=http%2Cvscode)
