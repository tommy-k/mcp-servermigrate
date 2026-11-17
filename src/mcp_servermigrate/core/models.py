from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Set, Literal
from enum import Enum

class InstallStrategy(str, Enum):
    DNF_REPO = "dnf_repo"
    TARBALL_DOWNLOAD = "tarball_download"
    PRELOADED_RECIPE = "preloaded_recipe"
    SOURCE_SYNC = "source_sync"
    HARDLINK = "hardlink"
    MANUAL_FLAG = "manual_flag"

class BinaryItem(BaseModel):
    path: str
    is_rpm_owned: bool
    package_name: Optional[str] = None
    group_owner: str = "root"
    acl_groups: List[str] = Field(default_factory=list)
    permissions: str = ""
    selinux_context: str = ""
    inode: Optional[int] = None
    link_count: int = 1
    is_executable: bool = True
    mode: Optional[str] = None

class DataFileItem(BaseModel):
    source_path: str
    target_path: str
    mode: str = "0644"
    owner: str = "root"
    group: str = "root"

class ModuleStreamItem(BaseModel):
    name: str
    stream: str
    profile: str = "common"

class PackageRecord(BaseModel):
    name: str
    version: str
    release: str
    vendor: str = ""
    is_redhat: bool = False

class GroupItem(BaseModel):
    name: str
    gid: Optional[int] = None
    members: List[str] = Field(default_factory=list)
    associated_apps: List[str] = Field(default_factory=list)
    description: Optional[str] = None

class CronEntry(BaseModel):
    user: str
    line: str
    is_custom: bool = True

class ServiceItem(BaseModel):
    name: str
    state: str
    is_enabled: bool

class ToolRecipe(BaseModel):
    name: str
    version: str = "latest"
    download_url: Optional[str] = None
    target_path: str = "/opt/tools/bin"
    group: str = "tool_users"
    archive_format: str = "tar.gz"
    binary_name: Optional[str] = None
    checksum_url: Optional[str] = None
    checksum_asset: Optional[str] = None

class BaselineEntry(BaseModel):
    kind: Literal["rpm", "service", "vendor_tree"]
    name: str
    on_source: bool
    on_target: bool
    enterprise: bool = False
    classification: Literal["BASELINE", "BASELINE_MISSING_ON_TARGET", "TARGET_ONLY", "CANDIDATE"]

class PlatformBaseline(BaseModel):
    entries: List[BaselineEntry] = Field(default_factory=list)
    excluded_paths: Set[str] = Field(default_factory=set)
    excluded_packages: Set[str] = Field(default_factory=set)
    excluded_services: Set[str] = Field(default_factory=set)

class ServerMigrationManifest(BaseModel):
    generation: int = 1
    parent_host: str
    migration_timestamp: str
    lineage_group: str = "mcp-migrate"
    tools: Dict[str, ToolRecipe] = Field(default_factory=dict)
    application_groups: Dict[str, List[str]] = Field(default_factory=dict)
    local_group: str = "tool_users"
    ad_group: str = "Domain Users"
    acl_path: str = "/opt/tools"
    learned_rules: List[str] = Field(default_factory=list)

class AppMigrationItem(BaseModel):
    name: str
    source_path: str
    target_path: str = "/opt/tools/bin"
    strategy: InstallStrategy
    version: str = "latest"
    download_url: Optional[str] = None
    archive_format: str = "tar.gz"
    target_group: str = "tool_users"
    permissions: str = "rx"
    hardlink_of: Optional[str] = None
    extra_groups: List[str] = Field(default_factory=list)
    checksum_url: Optional[str] = None
    checksum_asset: Optional[str] = None
    installed: bool = False

class ServerState(BaseModel):
    hostname: str
    os_release: str
    is_genesis: bool = True
    migration_manifest: Optional[ServerMigrationManifest] = None
    custom_groups: List[GroupItem] = Field(default_factory=list)
    baseline_rpms: List[str] = Field(default_factory=list)
    third_party_rpms: List[str] = Field(default_factory=list)
    installed_rpms: List[str] = Field(default_factory=list)
    unmanaged_binaries: List[BinaryItem] = Field(default_factory=list)
    data_files: List[DataFileItem] = Field(default_factory=list)
    module_streams: List[ModuleStreamItem] = Field(default_factory=list)
    vendor_trees: List[str] = Field(default_factory=list)
    root_crons: List[CronEntry] = Field(default_factory=list)
    running_services: List[ServiceItem] = Field(default_factory=list)
    profile_scripts: List[str] = Field(default_factory=list)
    posix_acls: Dict[str, str] = Field(default_factory=dict)
    informational_pam_rules: List[str] = Field(default_factory=list)

class RBACMapping(BaseModel):
    local_group: str
    ad_group: str
    target_path: str
    permissions: str = "rx"

class MigrationPlan(BaseModel):
    source_host: str
    target_host: str
    generation: int = 1
    is_genesis_migration: bool = True
    preloaded_recipes_used: List[str] = Field(default_factory=list)
    groups_to_create: List[GroupItem] = Field(default_factory=list)
    packages_to_install: List[str] = Field(default_factory=list)
    apps_to_install: List[AppMigrationItem] = Field(default_factory=list)
    symlinks_to_create: Dict[str, str] = Field(default_factory=dict)
    data_files_to_sync: List[DataFileItem] = Field(default_factory=list)
    flat_binaries_to_sync: List[str] = Field(default_factory=list)
    root_crons_to_apply: List[CronEntry] = Field(default_factory=list)
    rbac_mappings: List[RBACMapping] = Field(default_factory=list)
    profile_scripts_to_deploy: List[str] = Field(default_factory=list)
    module_streams: List[ModuleStreamItem] = Field(default_factory=list)
    platform_baseline: Optional[PlatformBaseline] = None
    informational_pam_rules: List[str] = Field(default_factory=list)
    skipped_items: List[str] = Field(default_factory=list)
    manifest_to_plant: Optional[ServerMigrationManifest] = None
    manifest_skill_markdown: Optional[str] = None
