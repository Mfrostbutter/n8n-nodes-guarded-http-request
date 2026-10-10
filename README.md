# n8n-nodes-guarded-http-request

An HTTP Request node for n8n with admin-controlled request policies. Platform
admins decide which methods, hosts, paths, headers, bodies, credentials and
network ranges a workflow may use. The decision is delivered through n8n's own
RBAC: a policy is a credential, and sharing that credential to a project is
what grants the project the policy.

Built for enterprise security reviews that block the stock HTTP Request node
("any editor can call anything, anywhere"). This node keeps the HTTP Request
surface editors know and puts the egress decision in the platform team's hands.

## How it works

Three layers. A request must pass every one of them.

| Layer | Who sets it | Where it lives | What it does |
|---|---|---|---|
| Instance floor | Platform admin | Config file on every n8n process (`N8N_GUARDED_HTTP_CONFIG`) | Hard limits nothing can widen: https only, no private networks, no manual `Authorization` headers, response size caps, and so on |
| Policy credential | Instance Owner or Admin | n8n credential of type **Guarded HTTP Policy**, shared to a project | Narrows the floor for one team: which hosts, which paths, which methods, which credential types |
| Node parameters | Workflow editor | The node on the canvas | The actual request. Rejected before it is sent if any layer disagrees |

The policy credential carries no secret. It carries either a **reference** to a
named policy in the instance config (recommended, policy stays in git) or an
**inline** JSON document. Inline documents can be required to carry an HMAC
signature made with a key only the platform team holds, so a project editor who
creates their own policy credential cannot mint permissions.

Enforcement happens at execution time, on every item, and on every redirect
hop. The editor UI shows the familiar HTTP Request fields; the node's "Inspect
Effective Policy" operation prints what the node may do.

### The RBAC tie-in

n8n checks at execution time that a workflow's project has access to every
credential the workflow uses. The policy credential rides on that check:

- The credential lives in the project it was created in, or was transferred to.
- Owners and Admins share it to other projects (Credentials > Share). Project
  Editors can use it in workflows but cannot read or change its contents.
- A workflow in a project that was not given the credential does not run at
  all: n8n refuses the whole execution with its own "does not have access to
  the credential" error before any node starts.
- Instance Owners and Admins bypass the credential access check in their own
  personal projects. That is n8n's behavior, not this node's. The floor still
  applies to them.

So "finance may GET the ERP, ops may POST to the ticketing API" is a credential
share, visible in n8n's sharing UI and audit log, not a workflow-level setting.

### Closing the side door

The policy only binds requests that go through this node. Pair it with:

```
NODES_EXCLUDE=["n8n-nodes-base.httpRequest","n8n-nodes-base.httpRequestTool"]
N8N_GUARDED_HTTP_REQUIRE_POLICY=true
```

so the stock HTTP Request node is gone and every Guarded request needs a policy
credential. Consider excluding other egress-capable nodes the review names
(Execute Command, SSH, Code with `this.helpers.httpRequest`), and setting
`N8N_BLOCK_ENV_ACCESS_IN_NODE=true`.

## Install

Zero runtime dependencies, one node, one credential type, built from `tsc`
with no native modules. Not eligible for the verified community node
program: it is a variant of a core node and reads instance configuration
from the environment.

Pick a distribution path. In queue mode the node must be present on **main,
every worker and every webhook process**, same version everywhere.

| Path | Steps |
|---|---|
| Mounted extensions dir | `npm run build`, copy `package.json` and `dist/` into `<dir>/n8n-nodes-guarded-http-request/`, set `N8N_CUSTOM_EXTENSIONS=<dir>` on every process. Node type is `CUSTOM.guardedHttpRequest`. |
| Private registry / community package | `npm publish` to the registry, install through Settings > Community nodes or `~/.n8n/nodes`. Node type is `n8n-nodes-guarded-http-request.guardedHttpRequest`. |
| Baked image | `COPY` the staged package into the image and set `N8N_CUSTOM_EXTENSIONS`. Recommended for Kubernetes and air-gapped estates. |

`scripts/stage-lab.sh` produces the staged layout (`.lab-stage/`).

n8n Cloud is not a target. Cloud does not accept private community nodes, and
this package is not eligible for the verified program.

## Configure the instance

| Variable | Purpose |
|---|---|
| `N8N_GUARDED_HTTP_CONFIG` | Path to the instance config JSON. Re-read when the file's mtime changes, no restart needed. A malformed file makes every request fail closed. |
| `N8N_GUARDED_HTTP_CONFIG_JSON` | Inline alternative to the file. |
| `N8N_GUARDED_HTTP_SIGNING_KEY` | `keyId:secret` (or just `secret`, key id `default`). Presence of any signing key turns on `requireSignedPolicies` unless the config says otherwise. |
| `N8N_GUARDED_HTTP_REQUIRE_POLICY` | `true` forces every node to carry a policy credential. Overrides the config file. |

Instance config shape (`examples/instance-config.json` is a full one):

```json
{
  "version": 1,
  "requirePolicy": true,
  "allowInlinePolicies": true,
  "requireSignedPolicies": true,
  "signingKeyFiles": { "2026-10": "/run/secrets/guarded-http-signing-key" },
  "floor": { "version": 1, "schemes": ["https"], "network": { "blockPrivate": true, "resolveDns": true } },
  "policies": {
    "finance-readonly": { "version": 1, "methods": ["GET"], "hosts": { "allow": ["erp.corp.example"] } }
  }
}
```

`signingKeys` (inline) and `signingKeyFiles` (paths) can both be set; several
key ids allow rotation. Keep the key in the customer's secret manager, never
in the config file that goes to git.

## Policy document

Every field is optional. An absent field means "no restriction from this
layer". Lists intersect across layers; booleans take the stricter value;
numbers take the minimum.

```json
{
  "version": 1,
  "name": "finance-readonly",
  "description": "shown in Inspect Effective Policy",
  "methods": ["GET", "HEAD"],
  "schemes": ["https"],
  "hosts": {
    "allow": ["api.example.com", "*.internal.corp", "10.20.0.0/16",
              { "host": "erp.corp.example", "paths": ["/api/v2/invoices/**"], "ports": [443] }],
    "deny": ["admin.internal.corp"]
  },
  "ports": [443],
  "paths": { "allow": ["/v1/**"], "deny": ["/v1/admin/**"] },
  "network": { "blockPrivate": true, "blockLoopback": true, "blockLinkLocal": true, "blockMetadata": true, "resolveDns": true },
  "redirects": { "follow": true, "max": 5, "sameHostOnly": false, "forwardAuthCrossHost": false },
  "headers": { "allow": ["accept", "content-type"], "deny": ["authorization", "cookie"] },
  "query": { "allow": [], "deny": ["api_key", "token"] },
  "body": { "allowed": true, "maxBytes": 1048576, "contentTypes": ["json", "form-urlencoded"] },
  "auth": { "required": true, "modes": ["predefinedCredentialType"], "credentialTypes": ["oAuth2Api", "httpHeaderAuth"] },
  "response": { "maxBytes": 10485760, "allowBinary": false },
  "options": { "allowSkipSslVerification": false, "maxTimeoutMs": 30000, "allowExpressionsInUrl": false, "allowProxy": false, "allowIgnoreResponseCode": false },
  "audit": { "log": true }
}
```

Notes on the semantics:

- **Hosts.** `*.example.com` matches subdomains, not the apex. CIDR patterns
  match IP-literal URLs only. A `{ host, paths, ports }` rule scopes paths and
  ports to that host. `hosts.deny` wins over `hosts.allow`.
- **Paths.** `*` is one segment, `**` is any depth. Dot segments are resolved
  by the URL parser before matching, so `/v1/../admin` is `/admin`.
- **Network.** `blockMetadata` is on unless every layer turns it off. With
  `resolveDns`, every A and AAAA answer for the host is classified; one private
  answer blocks the request. DNS rebinding between check and connect is not
  covered; put the resolver and egress controls at the network layer for that.
- **Redirects.** Each hop is re-evaluated against every layer with the method
  the hop will use. Credentials and `Authorization`, `Cookie` headers are
  dropped on a cross-host hop unless `forwardAuthCrossHost` is true.
- **Headers and query** names are compared case-insensitively. Denying
  `authorization` forces auth through n8n credentials, which is what a security
  review wants to see.
- **Expressions in URL.** With `allowExpressionsInUrl: false` the URL must be a
  static string, so what is reviewed is what runs. Query parameters can still be
  dynamic and are checked by name.
- **Auth** restricts the mode (none, predefined, generic) and the credential
  type names. The node cannot inspect credential contents and does not try.
- **Audit.** Every decision logs one line at `info`:
  `guarded-http allowed GET httpbin.org/get status=200 hops=0 policies=... workflow=... execution=...`,
  with the same fields as structured metadata when `N8N_LOG_FORMAT=json`.

## Policy credential

Settings > Credentials > **Guarded HTTP Policy**.

| Field | Use |
|---|---|
| Policy Name | Label in audit lines and error messages |
| Policy Source | **Reference an Instance Policy** (recommended) or **Inline Policy Document** |
| Instance Policy Name | Key under `policies` in the instance config |
| Policy JSON | Inline document |
| Signature | Output of `scripts/sign-policy.js`, required when the instance enforces signed policies |

Sign a policy:

```
GUARDED_HTTP_SIGNING_KEY=<secret> node scripts/sign-policy.js policy.json --key-id 2026-10
GUARDED_HTTP_SIGNING_KEY=<secret> node scripts/sign-policy.js policy.json --key-id 2026-10 --verify v1.2026-10.<hex>
```

The signature covers the canonical JSON (sorted keys), so whitespace and key
order do not matter but any value change invalidates it.

## The node

Operation **Send Request** mirrors the stock HTTP Request node: method, URL,
query, headers, body (JSON, form, multipart, raw, n8n binary), predefined or
generic credentials, batching, redirects, timeout, response format, full
response, never-error. Digest auth and pagination are not implemented.

Operation **Inspect Effective Policy** returns the merged view of what the node
may do, without sending anything. Hand it to editors who hit a block.

Option **Include Policy Info** adds `_guardedHttp` to each output item with the
policies applied, redirect hop count, final URL and status.

With **On Error > Continue**, a blocked item comes out as
`{ error, violations: [{ code, layer, message }] }` instead of stopping the run.

## Develop

```
npm install --ignore-scripts
npm run build
npm test
```

`--ignore-scripts` skips `isolated-vm`, a transitive dev dependency of
`n8n-workflow` that needs a native toolchain and is not used here.

Tested against n8n 2.35.5 (`examples/workflows/` hold the smoke workflows that
were run on it). `lab/` holds the config used by the local lab instance.

## Limitations

- Enforcement is in-process. A user who can install nodes or run arbitrary
  code on the instance can bypass it; this node is a control for workflow
  editors, not for instance admins.
- Response size is enforced after the body is received, with a Content-Length
  pre-check. Streaming cut-off is not implemented.
- DNS rebinding and connection-level controls belong to the network layer.
- Owners and Admins bypass n8n's credential access check in their personal
  projects, so test RBAC behavior with Member accounts.
