# Guarded HTTP Request: setup instructions

Companion to the walkthrough videos. Two cuts share the same footage:

| Video | Audience | Length |
|---|---|---|
| [Admin walkthrough](https://www.loom.com/share/780fd2c8dfc340508a1cfc12d42bee80) | Platform and security teams: how to configure and operate it | 4:11 |
| [Overview](LOOM_OVERVIEW_URL) | Customer stakeholders and CSMs: what it is and what it gives you | 1:50 |

Source: this repo. The README has the full policy schema.

## 1. Install the node on every n8n process

Build once, then put `package.json` and `dist/` under a directory n8n loads as custom extensions:

```
npm install --ignore-scripts && npm run build
# stage: <ext-dir>/n8n-nodes-guarded-http-request/{package.json,dist/}
N8N_CUSTOM_EXTENSIONS=<ext-dir>
```

In queue mode the node must be present on main, every worker and every webhook process, same version everywhere. For Kubernetes or air-gapped estates bake it into the image.

## 2. Write the instance config

One JSON file, pointed at by `N8N_GUARDED_HTTP_CONFIG`. It reloads when its mtime changes; a malformed file makes every request fail closed.

```json
{
  "version": 1,
  "requirePolicy": true,
  "allowInlinePolicies": false,
  "floor": {
    "version": 1,
    "schemes": ["https"],
    "network": { "blockPrivate": true, "blockLoopback": true, "blockLinkLocal": true, "blockMetadata": true, "resolveDns": true },
    "headers": { "deny": ["authorization", "cookie", "proxy-authorization"] },
    "redirects": { "max": 5, "forwardAuthCrossHost": false },
    "response": { "maxBytes": 10485760 },
    "options": { "allowSkipSslVerification": false, "allowProxy": false, "maxTimeoutMs": 60000 }
  },
  "policies": {
    "finance-readonly": {
      "version": 1,
      "methods": ["GET", "HEAD"],
      "hosts": { "allow": [{ "host": "erp.corp.example", "paths": ["/api/v2/invoices/**"] }, "rates.example.com"] },
      "body": { "allowed": false },
      "options": { "allowExpressionsInUrl": false }
    },
    "ops-write": {
      "version": 1,
      "methods": ["GET", "POST", "PATCH"],
      "hosts": { "allow": ["tickets.corp.example"] },
      "body": { "maxBytes": 262144, "contentTypes": ["json"] },
      "query": { "deny": ["api_key", "token"] }
    }
  }
}
```

- `floor` applies to everyone and nothing can widen it.
- `policies` is the catalog that credentials point at. Lists intersect across layers, booleans take the stricter value, numbers the minimum.
- `requirePolicy: true` means every node needs a policy credential.
- `allowInlinePolicies: false` means credentials may only reference catalog entries. If you allow inline policies, set a signing key (`N8N_GUARDED_HTTP_SIGNING_KEY=keyid:secret`) so only the platform team can mint them; sign with `scripts/sign-policy.js`.

## 3. Create a policy credential per team

As an instance Owner or Admin, inside the team's project: Create credential > Guarded HTTP Policy.

| Field | Value |
|---|---|
| Name | something editors will recognise, e.g. `Policy: finance read-only` |
| Policy Source | Reference an Instance Policy |
| Instance Policy Name | the catalog key, e.g. `finance-readonly` |

Save. The credential holds no secret; it holds the pointer. Creating it inside the project is the grant: every editor in the project can use it, none can open or edit it. The Sharing tab adds further projects or users.

## 4. Close the side door

```
NODES_EXCLUDE=["n8n-nodes-base.httpRequest","n8n-nodes-base.httpRequestTool"]
N8N_GUARDED_HTTP_REQUIRE_POLICY=true
```

The first removes the stock HTTP Request node. The second refuses any Guarded node without a policy credential. Consider also excluding Execute Command and SSH, and setting `N8N_BLOCK_ENV_ACCESS_IN_NODE=true`.

## 5. What editors see

- Add **Guarded HTTP Request**, pick the policy credential, fill in method, URL, headers, body as with HTTP Request. Run it.
- Allowed requests return the response like any HTTP node. With **Include Policy Info** on, each item carries `_guardedHttp` with the policies applied, redirect hops, final URL and status.
- Blocked requests fail before sending with a message naming the layer and the rule, e.g. `[finance-readonly] method POST is not allowed (allowed: GET, HEAD)`. With On Error set to continue, the item comes out as `{ error, violations }` instead of stopping the run.
- **Inspect Effective Policy** (Operation dropdown) prints the merged view of what the node may do without sending anything.

## 6. Verify and audit

- Every decision logs one `info` line: `guarded-http allowed|blocked METHOD host/path status=... policies=... workflow=... execution=...`. Use `N8N_LOG_FORMAT=json` for structured fields.
- Test RBAC with a Member account: a workflow in a project that was not given the credential does not run at all. Owners and Admins bypass n8n's credential access check in their personal projects.

## 7. Policies from a secret manager (optional)

n8n External Secrets (Enterprise) resolves `{{ $secrets.<vault>.<name> }}` inside credential fields, and the policy credential is nothing but fields. Supported stores include Infisical (n8n 2.26.0 or later, Universal Auth), AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, HashiCorp Vault and 1Password.

1. In the secret manager, create a machine identity that can read one path only, e.g. `/guarded-http` in one environment. Put the pointer there: `FINANCE_POLICY=finance-readonly`.
2. In n8n, Settings > External Secrets > Add secrets vault > Infisical: site URL, project ID, environment, secret path, client ID and client secret. Test, then save. Switch on "Enable external secrets for project roles" so project editors can run workflows whose credentials reference the vault.
3. In the policy credential, switch Instance Policy Name to an expression: `{{ $secrets.<vault key>.FINANCE_POLICY }}`, e.g. `{{ $secrets.Infisical.FINANCE_POLICY }}`. The vault key is the name you gave the connection. Inline mode works the same way with Policy JSON and Signature read from the store.

Which policy a team gets is now a value in the secret manager, with its audit trail and approval flow. Vaults can be scoped to one n8n project, so only that project's credentials may reference them. Secret values must be plain strings. The instance config file and the signing key are not credential fields and stay deploy-time injected.

## Known limits

- Enforcement is in-process; it governs workflow editors, not instance admins.
- Digest auth and pagination are not implemented in this version.
- Response size is enforced after download with a Content-Length pre-check; DNS rebinding is a network-layer concern.
