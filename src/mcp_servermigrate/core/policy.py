import re
from typing import Dict, List, Optional, Tuple, Set

# Enterprise agents pre-installed on platform baseline images (never to be copied)
ENTERPRISE_PACKAGE_MARKERS: Tuple[str, ...] = (
    "falcon",
    "tanium",
    "dynatrace",
    "oneagent",
    "managesoft",
    "splunk",
    "crowdstrike",
    "mgsusage",
    "fnms",
    "extrahop",
    "agent_linux",
    "qualys",
    "insights-client",
    "rhc",
    "rhcd",
)

ENTERPRISE_SERVICES: Tuple[str, ...] = (
    "falcon-sensor.service",
    "taniumclient.service",
    "oneagent.service",
    "mgsusageag.service",
    "ndtask.service",
    "insights-client.service",
    "agentcored.service",
    "SplunkForwarder.service",
    "rhcd.service",
)

ENTERPRISE_PATH_PREFIXES: Tuple[str, ...] = (
    "/opt/dynatrace",
    "/opt/CrowdStrike",
    "/opt/Tanium",
    "/opt/managesoft",
    "/opt/splunkforwarder",
)

SUPERSEDED_BY_PODMAN: Set[str] = {
    "docker-ce",
    "docker-ce-cli",
    "containerd.io",
    "docker-buildx-plugin",
    "docker-compose-plugin",
    "docker",
}

# Red Hat / Enterprise Linux Official PGP Key Signatures
REDHAT_PGP_KEYS = {
    "fd431d51",  # Red Hat Enterprise Linux 8
    "5a6340b3",  # Red Hat Enterprise Linux 9
    "199e2f91",  # Red Hat Enterprise Linux 8 / 9 Beta
    "8a29b029",  # Fedora 38/39/40/41/42/43/44
    "6d745a60",  # Rocky Linux 8
    "350d275d",  # Rocky Linux 9
    "ced7258b",  # AlmaLinux 8
    "51d66477",  # AlmaLinux 9
}

MODULE_STREAM_RE = re.compile(r"^[a-zA-Z0-9_-]+:[a-zA-Z0-9_.-]+$")
GROUP_NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]*[$]?$")
RESERVED_GROUPS = {
    "root", "bin", "daemon", "sys", "adm", "tty", "disk", "lp", "mem", "kmem", "wheel"
}

KNOWN_VENDOR_CHECKSUMS = {
    "terraform": "https://releases.hashicorp.com/terraform/{version}/terraform_{version}_SHA256SUMS",
    "gh": "https://github.com/cli/cli/releases/download/v{version}/gh_{version}_checksums.txt",
}

def is_enterprise_marker(name: str) -> bool:
    name_lower = name.lower()
    return any(marker in name_lower for marker in ENTERPRISE_PACKAGE_MARKERS)

def is_enterprise_service(service_name: str) -> bool:
    name_lower = service_name.lower()
    return any(name_lower == svc.lower() or is_enterprise_marker(name_lower) for svc in ENTERPRISE_SERVICES)

def is_enterprise_path(path: str) -> bool:
    path_lower = path.lower()
    return any(path_lower.startswith(prefix.lower()) or is_enterprise_marker(path_lower) for prefix in ENTERPRISE_PATH_PREFIXES)

def is_redhat_vendor(vendor: str, signature: str = "") -> bool:
    """Accurately checks whether a package is official OS vendor signed."""
    if signature:
        for key in REDHAT_PGP_KEYS:
            if key in signature.lower():
                return True
    
    v_clean = (vendor or "").strip().lower()
    if not v_clean or v_clean == "(none)":
        return False
        
    return any(lead in v_clean for lead in ("red hat", "rocky", "almalinux", "fedora", "centos", "oracle"))
