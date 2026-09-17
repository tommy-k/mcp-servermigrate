# 🚀 MCP ServerMigrate Agent

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform: Enterprise Linux](https://img.shields.io/badge/Platform-RHEL%20%7C%20Rocky%20%7C%20Alma%20%7C%20Fedora-CC0000.svg)](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-Model%20Context%20Protocol-8A2BE2.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An intelligent, enterprise-grade **Model Context Protocol (MCP)** agent designed for migrating, modernizing, and auditing **Enterprise Linux** servers (Red Hat Enterprise Linux, Rocky Linux, AlmaLinux, Oracle Linux, CentOS Stream, and Fedora).

Built specifically for **domain-joined, policy-managed environments** (SSSD, Active Directory, Red Hat Satellite, GPO baselines), `mcp-servermigrate` bridges the gap between central compliance baselines and application-level customizations.

---

## 🌟 Key Features

* 🔍 **Phase 1: Deep Discovery & Lineage Detection**
  * Differentiates OS/Satellite-managed RPMs from unmanaged binaries (`terraform`, `gh`, `rclone`, `kubectl`, custom binaries in `/opt` and `/usr/local/bin`).
  * Automatically detects **Genesis vs. Generational Hosts** by inspecting on-server migration records (`/etc/mcp-migration/manifest.json`).
* 📦 **Phase 2: Universal Dynamic Release Resolver**
  * Proactively resolves **latest stable upstream releases** for tools not in Red Hat repositories (HashiCorp, GitHub Releases, vendor endpoints).
  * Automatically handles universal archives (`.tar.gz`, `.zip`, `.tgz`, raw binaries) and stages them into `/opt/tools/bin/`.
* 🛡️ **Phase 3: Decoupled RBAC & Shell Layering**
  * Bridges Active Directory identities to local semantic role groups (`tool_users`, `app_operators`) via PAM (`/etc/security/group.conf`).
  * Applies **POSIX ACLs with default inheritance (`-d`)** so all newly deployed tools inherit execution permissions for domain users.
  * Injects global tool paths non-destructively via `/etc/profile.d/corp-standards.sh` while preserving user customizability in `~/.bashrc`.
* 🧠 **Phase 4: On-Server Migration Skill & Lineage Recording**
  * Plants a persistent machine-readable manifest (`/etc/mcp-migration/manifest.json`) and an operational skill (`/etc/mcp-migration/SKILL.md`) on target hosts.
  * **Generational Inheritance:** Future migrations from Server 2 to Server 3 automatically preload verified recipes, permissions, and URLs learned during previous runs.
* 🔐 **Safe Staged Execution with Ephemeral Credentials**
  * Rotating sudo passwords stay in volatile RAM—never leaked into LLM prompts, disk, or logs.
  * Interactive human-in-the-loop approval gates before elevated mutations (with optional `--auto-approve-sudo` bypass).
* 🩺 **Post-Flight Health Verification**
  * Audits SELinux denial logs (`ausearch -m avc`) and ensures `bin_t` context is enforced.
  * Verifies listening sockets (`ss -tulpn`) and systemd service health.

---

## 🏗️ Architecture & Deployment Topologies

```mermaid
flowchart TD
    subgraph ModeA["Mode A: Workstation Orchestrator"]
        Workstation["Workstation / AI Agent<br/>(Cursor, Antigravity, Claude)"]
        Workstation -->|"SSH (Read-Only)"| SrvX_A["Source Server X"]
        Workstation -->|"SSH (Staged Execution)"| SrvY_A["Target Server Y"]
    end

    subgraph ModeB["Mode B: Source-Host Execution"]
        RemoteIDE["Remote Session / IDE<br/>(Cursor Remote-SSH on Server X)"]
        RemoteIDE -->|"Local Audit"| SrvX_B["Source Server X (Localhost)"]
        RemoteIDE -->|"SSH and rsync"| SrvY_B["Target Server Y (Remote)"]
    end
```

---

## 🧬 Generational Lineage Workflow

```mermaid
flowchart LR
    subgraph Gen0["Genesis Run (Server 1 -> Server 2)"]
        S1["Server 1 (Genesis)<br/>No prior history"] --> Plan1["Deep Research & Discovery<br/>Resolves Upstream Tarballs"]
        Plan1 --> S2["Server 2 (Generation 1)<br/>Plants /etc/mcp-migration/"]
    end

    subgraph Gen1["Generational Run (Server 2 -> Server 3)"]
        S2 -->|Preloads Verified Recipes| Plan2["Smart Plan<br/>Zero Redundant Prompts"]
        Plan2 --> S3["Server 3 (Generation 2)<br/>Lineage Updated"]
    end
```

---

## 📥 Installation

Clone the repository and set up a virtual environment in your preferred workspace directory:

```bash
# 1. Clone the repository
git clone https://github.com/<your-org>/mcp-servermigrate.git
cd mcp-servermigrate

# 2. Initialize and activate Python virtual environment (Python 3.11+)
python3 -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode
pip install --upgrade pip
pip install -e .
```

---

## 🚀 How to Run (MCP Agent Integration)

`mcp-servermigrate` is designed primarily as an **MCP (Model Context Protocol) Server**, providing your AI agent (Cursor, Antigravity, Claude Desktop, etc.) with direct tools to audit and migrate servers.

Choose the deployment mode that fits your environment:

### Mode A: Local Execution on Your Workstation (Windows / macOS / Linux / WSL)

The MCP server runs on your local machine or jump host. The AI agent connects to both Source and Target servers remotely over SSH, leaving **zero software footprint** on either server.

#### 1. Native Linux / macOS Workstation Configuration
Add this entry to your client's MCP configuration file (e.g., `mcp_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "server-migrate": {
      "command": "<path-to-repo>/.venv/bin/python",
      "args": ["-m", "mcp_servermigrate.server"]
    }
  }
}
```

#### 2. Windows Host (Bridging into WSL) Configuration
If your AI IDE runs on Windows and the project is hosted inside WSL:

```json
{
  "mcpServers": {
    "server-migrate": {
      "command": "wsl.exe",
      "args": [
        "-d", "<your-wsl-distro-name>",
        "bash", "-c",
        "cd <path-to-repo> && source .venv/bin/activate && python -m mcp_servermigrate.server"
      ]
    }
  }
}
```

---

### Mode B: Local Execution on the Server (Source Server X)

The MCP server runs directly on the source server (Server X)—ideal if you are connecting via **Cursor Remote-SSH** or running an on-box agent session.

#### 1. Cursor Remote-SSH Workspace
When Cursor is connected directly to Server X, add this to the workspace's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "server-migrate": {
      "command": "<path-to-repo-on-server>/.venv/bin/python",
      "args": ["-m", "mcp_servermigrate.server"]
    }
  }
}
```

#### 2. Remote SSH Pipe (Local Agent $\rightarrow$ Remote Server)
If your local AI agent wants to execute the MCP server remotely on Server X without opening a full remote IDE session:

```json
{
  "mcpServers": {
    "server-migrate-remote": {
      "command": "ssh",
      "args": [
        "-T",
        "<user>@<source-server-host>",
        "<path-to-repo-on-server>/.venv/bin/python -m mcp_servermigrate.server"
      ]
    }
  }
}
```

---

## 🛠️ Exposed MCP Tools

Once connected, your AI assistant will have access to the following tools:

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `audit_host` | `host`, `user` | Performs a deep audit of a server, checks for `/etc/mcp-migration/manifest.json`, and returns structured JSON telemetry. |
| `create_migration_plan` | `source_host`, `target_host`, `user` | Performs gap analysis, preloads verified recipes from prior lineage if present, resolves upstream releases, and generates an actionable plan. |
| `execute_migration` | `source_host`, `target_host`, `user` | Executes the migration, downloads tarball CLI tools, deploys RBAC and profile baselines, and plants the on-server `SKILL.md` lineage. |

---

## 🧪 Testing

Run the automated test suite on your host:

```bash
source .venv/bin/activate
pytest tests/ -v
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
