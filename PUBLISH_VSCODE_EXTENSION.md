# Publish and use the Ch3ck3r VS Code extension

This guide covers Ch3ck3r SAST **1.2.0** in `vscode-extension/`.

> **You do not need a Marketplace subscription, publisher, PAT, or payment to test the extension locally.** Install the VSIX first and publish only after local testing succeeds.

> Publishing makes the extension public. Review the package before running the final publish command. Never commit or paste a Marketplace token into this repository, a script, a screenshot, or shell history.

## Test locally first — no subscription required

Install the already verified package:

```bash
code --install-extension \
  /home/remnant01/Documents/PROJECTS/ch3ck3r/vscode-extension/ch3ck3r-sast-1.2.0.vsix \
  --force
```

Verify installation:

```bash
code --list-extensions --show-versions | \
  grep '^remnant01\.ch3ck3r-sast@1.2.0$'
```

Open a safe local test project:

```bash
code /path/to/your/test-project
```

In VS Code:

1. Reload the window if VS Code was already open.
2. Open a JavaScript, TypeScript, Python, Go, Java, YAML, JSON, Dockerfile, or Terraform file.
3. Press `Ctrl+Shift+P`.
4. Run **Ch3ck3r: Scan Current File**.
5. Review results in **View → Problems** and the Ch3ck3r Security Explorer.
6. Run **Ch3ck3r: Scan Workspace Folder** on a controlled test repository.
7. Test report output with **Ch3ck3r: Show Scan Report**.

Do not test backend/DAST features against external systems unless you own them or have explicit authorization.

To remove the private test build:

```bash
code --uninstall-extension remnant01.ch3ck3r-sast
```

Marketplace setup is necessary only when you are ready to make the extension public.

## Marketplace publishing prerequisites

- Node.js 22 or another version compatible with `package.json`
- npm
- A Microsoft/Azure DevOps account
- A Visual Studio Marketplace publisher whose immutable ID is exactly `remnant01`
- Permission to publish under the `remnant01` publisher

The extension manifest currently contains:

```json
{
  "name": "ch3ck3r-sast",
  "publisher": "remnant01",
  "version": "1.2.0"
}
```

The extension is now configured for Marketplace identity `remnant01.ch3ck3r-sast`. The publisher display name can be styled differently, but its immutable ID must be `remnant01`.

## 1. Create or confirm the publisher

1. Open <https://marketplace.visualstudio.com/manage>.
2. Sign in with your Microsoft account.
3. Select **Create publisher**.
4. Enter `remnant01` in the immutable **ID** field.
5. Enter your preferred public display name, such as `Remnant01`, in the **Name** field.
6. Complete the requested publisher profile fields and select **Create**.
7. Confirm that your signed-in account is listed as an owner or contributor for the publisher.

If Marketplace reports that `remnant01` is unavailable, do not publish under somebody else's account. Choose a new available publisher ID, then change the `publisher` field in `vscode-extension/package.json` and replace `remnant01` in the commands below before rebuilding.

Publisher IDs cannot be renamed after creation. Do not change the manifest to an ID you do not control.

## 2. Create a Marketplace token

For manual CLI publishing, create an Azure DevOps Personal Access Token:

1. Open <https://dev.azure.com/> and select your organization.
2. Open **User settings → Personal access tokens → New Token**.
3. Select **Custom defined** scopes.
4. Choose **Marketplace → Manage** only.
5. Use the shortest practical expiration period.
6. Copy the token into a password manager.

For long-term automated publishing, Microsoft recommends Entra ID/workload identity rather than a long-lived PAT.

## 3. Restore dependencies and run release gates

From the repository root:

```bash
cd /home/remnant01/Documents/PROJECTS/ch3ck3r/vscode-extension
npm ci --ignore-scripts
npm run check
npm run test:coverage
npm audit --audit-level=high
npm run security:gates
npm run package:vsix
npm run security:gates
npm run sbom
```

Expected release artifact:

```text
ch3ck3r-sast-1.2.0.vsix
```

The package inspection must pass after packaging. Do not publish if tests, audit, SBOM generation, or the VSIX allowlist fails.

## 4. Inspect the final package

```bash
npx --no-install vsce ls --tree
unzip -Z1 ch3ck3r-sast-1.2.0.vsix
sha256sum ch3ck3r-sast-1.2.0.vsix
```

The VSIX should contain runtime source, `package.json`, README, changelog, license, security policy, usage documentation, and approved media. It must not contain `.env` files, tokens, databases, test fixtures, `node_modules`, private keys, or local reports.

## 5A. Publish with the CLI

Authenticate through the interactive prompt so the PAT is not written into a command:

```bash
npx --no-install vsce login remnant01
```

When prompted, paste the PAT. Then publish the already inspected VSIX:

```bash
npx --no-install vsce publish \
  --packagePath ch3ck3r-sast-1.2.0.vsix
```

After publishing, open:

```text
https://marketplace.visualstudio.com/items?itemName=remnant01.ch3ck3r-sast
```

Verify the icon, README, version, installation button, repository URL, license, and changelog.

## 5B. Publish manually in the browser

If you prefer not to authenticate the CLI:

1. Open <https://marketplace.visualstudio.com/manage>.
2. Select the `remnant01` publisher.
3. Select **New extension → Visual Studio Code**.
4. Upload `vscode-extension/ch3ck3r-sast-1.2.0.vsix`.
5. Review the Marketplace preview and publish.

Only one of the CLI or browser methods is required.

## Publishing the next update

Marketplace versions are immutable. You cannot overwrite an existing `1.2.0` release. For the next patch, choose a new semantic version, for example `1.2.1`:

```bash
cd /home/remnant01/Documents/PROJECTS/ch3ck3r/vscode-extension
npm version 1.2.1 --no-git-tag-version --ignore-scripts
```

Update `CHANGELOG.md`, any version-specific examples, and release notes. Then repeat all release gates and publish the new VSIX:

```bash
npm ci --ignore-scripts
npm run check
npm run test:coverage
npm audit --audit-level=high
npm run security:gates
npm run package:vsix
npm run security:gates
npm run sbom
npx --no-install vsce publish \
  --packagePath ch3ck3r-sast-1.2.1.vsix
```

Do not use `vsce publish patch/minor/major` in a dirty working tree: it can modify the version and create Git version commits/tags. This repository currently has a large generated-file cleanup pending review, so explicit versioning is safer.

## Install before Marketplace publication

Install the inspected VSIX locally:

```bash
code --install-extension \
  /home/remnant01/Documents/PROJECTS/ch3ck3r/vscode-extension/ch3ck3r-sast-1.2.0.vsix
```

To reinstall the same build:

```bash
code --install-extension \
  /home/remnant01/Documents/PROJECTS/ch3ck3r/vscode-extension/ch3ck3r-sast-1.2.0.vsix \
  --force
```

Restart or reload VS Code after installation.

## Install from the Marketplace

After publication:

1. Open VS Code.
2. Open **Extensions** with `Ctrl+Shift+X`.
3. Search for `Ch3ck3r SAST` or `remnant01.ch3ck3r-sast`.
4. Select **Install**.
5. Open a trusted project folder.

CLI installation from the Marketplace:

```bash
code --install-extension remnant01.ch3ck3r-sast
```

## Use the extension

### Scan the current file

1. Open a JavaScript, TypeScript, Python, Go, Java, Ruby, Rust, YAML, JSON, Dockerfile, or Terraform file.
2. Open the Command Palette with `Ctrl+Shift+P`.
3. Run **Ch3ck3r: Scan Current File**.

Shortcut:

```text
Ctrl+Shift+C
```

On macOS, use `Cmd+Shift+C`.

### Scan a workspace

1. Open a project folder in VS Code.
2. Decide whether you trust the workspace.
3. Run **Ch3ck3r: Scan Workspace Folder** from the Command Palette.
4. Review findings in the **Problems** panel and Ch3ck3r Security Explorer.

Large workspaces are bounded by file-size, file-count, depth, and concurrency settings.

### Scan an OpenAPI specification

Open a YAML or JSON OpenAPI/Swagger file and run:

```text
Ch3ck3r: Scan OpenAPI/Swagger Spec
```

The extension performs local structural and heuristic security checks. It is not a complete OpenAPI schema validator.

### Review findings

- Select a finding in the Ch3ck3r explorer to navigate to its location.
- Hover over highlighted code for an explanation and references.
- Open the Problems panel with `Ctrl+Shift+M`.
- Treat findings as review signals: false positives and false negatives are possible.
- Review every suggested edit and run application tests afterward.

### Generate a report

Choose the report format in VS Code settings:

```json
{
  "ch3ck3r.reportFormat": "sarif"
}
```

Supported formats are `sarif`, `json`, `markdown`, and `html`.

Run:

```text
Ch3ck3r: Show Scan Report
```

Reports are redacted and escaped, but filenames and security observations can still be sensitive.

### Configure automatic scanning

Example workspace settings:

```json
{
  "ch3ck3r.enabled": true,
  "ch3ck3r.autoScanOnSave": true,
  "ch3ck3r.autoScanOnOpen": true,
  "ch3ck3r.autoScanOnStart": false,
  "ch3ck3r.severityThreshold": "medium",
  "ch3ck3r.maxFileSizeKB": 1024,
  "ch3ck3r.maxWorkspaceFiles": 5000,
  "ch3ck3r.maxScanConcurrency": 4,
  "ch3ck3r.excludePatterns": [
    "**/node_modules/**",
    "**/.git/**",
    "**/dist/**",
    "**/build/**"
  ]
}
```

Use settings supported by the installed version; VS Code provides completion from the extension manifest.

## Optional backend operations

Local built-in SAST runs offline. Backend scans are separate, explicit operations.

1. Trust the workspace.
2. Run **Ch3ck3r: Connect to Ch3ck3r Backend**.
3. Enter an HTTPS backend URL. Plain HTTP is allowed only for loopback development.
4. Enter the token when prompted. It is stored in VS Code SecretStorage.
5. Run **Ch3ck3r: Run Full Security Scan (Backend)** only against an authorized target.
6. Confirm the displayed target before sending the request.

Delete the saved token with:

```text
Ch3ck3r: Delete Stored Backend Token
```

Never scan an external system without authorization.

## Remove the extension

```bash
code --uninstall-extension remnant01.ch3ck3r-sast
```

You can also uninstall it from the VS Code Extensions view.

## Troubleshooting

### Publisher error

Confirm that:

- `package.json` contains the publisher ID you own;
- your account is a member of that publisher;
- the PAT has only `Marketplace: Manage` and has not expired.

### Version already exists

Increment the version, update the changelog, rebuild, reinspect, and publish the new VSIX. Existing Marketplace versions cannot be replaced.

### `vsce` is unavailable

Restore locked dependencies:

```bash
cd /home/remnant01/Documents/PROJECTS/ch3ck3r/vscode-extension
npm ci --ignore-scripts
npx --no-install vsce --version
```

### Local scan shows no findings

Check that Ch3ck3r is enabled, the file language is supported, the severity threshold is not too high, and the file is not excluded or above configured limits.

## Security notes

- Publishing is an external and effectively public action; perform it only after maintainer approval.
- Never store `VSCE_PAT` in `.env`, repository secrets visible to forks, source code, or scripts.
- Rotate a PAT immediately if exposed.
- Prefer short-lived credentials and least privilege.
- Keep the generated SBOM and VSIX SHA-256 with release evidence.
- Read `vscode-extension/SECURITY.md`, `THREAT_MODEL.md`, and `FINAL_VERIFICATION.md` before release.

## Official references

- Publishing extensions: <https://code.visualstudio.com/api/working-with-extensions/publishing-extension>
- Publisher management: <https://marketplace.visualstudio.com/manage>
- Marketplace: <https://marketplace.visualstudio.com/vscode>
