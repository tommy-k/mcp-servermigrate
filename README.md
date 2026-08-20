# 🚀 MCP ServerMigrate Agent

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform: RHEL/Fedora](https://img.shields.io/badge/Platform-RHEL%20%7C%20Fedora-CC0000.svg)](https://www.redhat.com/en/technologies/linux-platforms/enterprise-linux)
[![Protocol: MCP](https://img.shields.io/badge/Protocol-Model%20Context%20Protocol-8A2BE2.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An intelligent, enterprise-grade **Model Context Protocol (MCP)** agent designed for migrating, modernizing, and auditing **RHEL & Fedora** servers.

Built specifically for **domain-joined, policy-managed environments** (SSSD, Active Directory, Red Hat Satellite, GPO baselines), `mcp-servermigrate` bridges the gap between central compliance baselines and application-level customizations.

---

## 🌟 Key Features

* 🔍 **Phase 1: Deep Discovery & Gap Analysis**
  * Differentiates OS/Satellite-managed RPMs from unmanaged flat binaries and standalone tools (`gh`, `rclone`, custom binaries in `/opt` and `/usr/local/bin`).
  * Discovers running systemd services, active listening sockets (`ss`), and custom root crontabs without picking up baseline noise.
* 🛡️ **Phase 2: Decoupled RBAC & Shell Layering**
  * Bridges Active Directory identities to local semantic role groups (`tool_users`, `app_operators`) via PAM (`/etc/security/group.conf`).
  * Applies **POSIX ACLs with default inheritance (`-d`)** so new binaries automatically inherit least-privilege permissions.
  * Deploys system-wide non-destructive shell standards in `/etc/profile.d/` while preserving full user customization in `~/.bashrc`.
* 🔐 **Phase 3: Safe Staged Execution with Ephemeral Credentials**
  * Rotating sudo passwords live strictly in **volatile memory**—never leaked into LLM contexts, logs, or disk.
  * Interactive human-in-the-loop approval gates before any elevated mutation (with optional `--auto-approve-sudo` bypass).
  * True enterprise sync preserving extended attributes and ACLs (`rsync -avAX`).
* 🩺 **Phase 4: Post-Flight Health Verification**
  * Scans SELinux audit logs (`audit.log`) for `AVC` denials (`ausearch -m avc`).
  * Verifies systemd unit statuses, active listening ports, and filesystem ACL bindings.

---

## 🏗️ Architecture & Deployment Topologies

```mermaid
flowchart TD
    subgraph ModeA["Mode A: Workstation Orchestrator (Windows / macOS / Linux)"]
        Workstation["Workstation / AI Agent<br/>(Cursor, Antigravity, Claude)"]
        Workstation -->|SSH (Read-Only)| SrvX_A["Source Server X"]
        Workstation -->|SSH (Staged Execution)| SrvY_A["Target Server Y"]
    end

    subgraph ModeB["Mode B: Source-Host Execution (Direct on Server X)"]
        RemoteIDE["Remote Session / IDE<br/>(Cursor Remote-SSH on Server X)"]
        RemoteIDE -->|Local Audit / Inspection| SrvX_B["Source Server X (Localhost)"]
        RemoteIDE -->|SSH / rsync| SrvY_B["Target Server Y (Remote)"]
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
| `audit_host` | `host`, `user` | Performs a deep, read-only audit of a server (RPM packages, unmanaged binaries in `/opt`, crons, systemd units, and ACLs). |
| `create_migration_plan` | `source_host`, `target_host`, `user` | Performs gap analysis between source and target, mapping decoupled RBAC rules and generating an actionable migration plan. |
| `execute_migration` | `source_host`, `target_host`, `user` | Executes the migration plan with interactive sudo confirmation gates and runs post-flight verification. |

---

## 🧪 Testing

Run the automated test suite on your host:

```bash
source .venv/bin/activate
pytest tests/
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
