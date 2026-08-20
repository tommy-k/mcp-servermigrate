from mcp_servermigrate.core.models import ServerState, MigrationPlan, RBACMapping

class MigrationPlanner:
    def __init__(self, source_state: ServerState, target_state: ServerState):
        self.src = source_state
        self.tgt = target_state

    def generate_plan(self) -> MigrationPlan:
        flat_binaries = [
            b.path for b in self.src.unmanaged_binaries if not b.is_rpm_owned
        ]

        rbac = [
            RBACMapping(
                local_group="tool_users",
                ad_group="Domain Users",
                target_path="/opt/tools",
                permissions="rx"
            )
        ]

        profile_scripts = [
            p for p in self.src.profile_scripts if not p.endswith(("/sh.local", "/bash_completion.sh"))
        ]

        return MigrationPlan(
            source_host=self.src.hostname,
            target_host=self.tgt.hostname,
            flat_binaries_to_sync=flat_binaries,
            root_crons_to_apply=self.src.root_crons,
            rbac_mappings=rbac,
            profile_scripts_to_deploy=profile_scripts
        )
