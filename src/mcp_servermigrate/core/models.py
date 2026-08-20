from pydantic import BaseModel, Field
from typing import List, Dict, Optional

class BinaryItem(BaseModel):
    path: str
    is_rpm_owned: bool
    package_name: Optional[str] = None
    permissions: str = ""
    selinux_context: str = ""

class CronEntry(BaseModel):
    user: str
    line: str
    is_custom: bool = True

class ServiceItem(BaseModel):
    name: str
    state: str
    is_enabled: bool

class ServerState(BaseModel):
    hostname: str
    os_release: str
    baseline_rpms: List[str] = Field(default_factory=list)
    third_party_rpms: List[str] = Field(default_factory=list)
    unmanaged_binaries: List[BinaryItem] = Field(default_factory=list)
    root_crons: List[CronEntry] = Field(default_factory=list)
    running_services: List[ServiceItem] = Field(default_factory=list)
    profile_scripts: List[str] = Field(default_factory=list)
    posix_acls: Dict[str, str] = Field(default_factory=dict)

class RBACMapping(BaseModel):
    local_group: str
    ad_group: str
    target_path: str
    permissions: str = "rx"

class MigrationPlan(BaseModel):
    source_host: str
    target_host: str
    flat_binaries_to_sync: List[str] = Field(default_factory=list)
    root_crons_to_apply: List[CronEntry] = Field(default_factory=list)
    rbac_mappings: List[RBACMapping] = Field(default_factory=list)
    profile_scripts_to_deploy: List[str] = Field(default_factory=list)
    services_to_enable: List[str] = Field(default_factory=list)
