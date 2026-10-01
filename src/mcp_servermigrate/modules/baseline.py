from typing import List, Set, Literal
from mcp_servermigrate.core.models import BaselineEntry, PlatformBaseline
from mcp_servermigrate.core.policy import (
    is_enterprise_marker,
    is_enterprise_path,
    is_enterprise_service,
    ENTERPRISE_PATH_PREFIXES
)

class BaselineComparator:
    """Phase 0: Compares source and target host platform baselines before planning."""

    @classmethod
    def compare(
        cls,
        src_rpms: Set[str],
        tgt_rpms: Set[str],
        src_services: Set[str],
        tgt_services: Set[str],
        src_vendor_trees: Set[str],
        tgt_vendor_trees: Set[str],
    ) -> PlatformBaseline:
        entries: List[BaselineEntry] = []
        excluded_paths: Set[str] = set()
        excluded_packages: Set[str] = set()
        excluded_services: Set[str] = set()

        # 1. Compare Vendor Trees (e.g. /opt/dynatrace, /opt/CrowdStrike, /opt/splunkforwarder)
        all_trees = src_vendor_trees | tgt_vendor_trees
        for tree in sorted(all_trees):
            on_src = tree in src_vendor_trees
            on_tgt = tree in tgt_vendor_trees
            is_ent = is_enterprise_path(tree) or any(tree.lower().startswith(p.lower()) for p in ENTERPRISE_PATH_PREFIXES)

            if on_src and on_tgt:
                classification = "BASELINE"
                excluded_paths.add(tree)
            elif on_tgt and not on_src:
                classification = "TARGET_ONLY"
                # Target-only platform tools must not be touched or overwritten
                excluded_paths.add(tree)
            elif on_src and not on_tgt:
                if is_ent:
                    classification = "BASELINE_MISSING_ON_TARGET"
                    # Enterprise agents missing on target must NEVER be copied
                    excluded_paths.add(tree)
                else:
                    classification = "CANDIDATE"

            entries.append(BaselineEntry(
                kind="vendor_tree",
                name=tree,
                on_source=on_src,
                on_target=on_tgt,
                enterprise=is_ent,
                classification=classification
            ))

        # 2. Compare RPM Packages
        all_rpms = src_rpms | tgt_rpms
        for pkg in sorted(all_rpms):
            on_src = pkg in src_rpms
            on_tgt = pkg in tgt_rpms
            is_ent = is_enterprise_marker(pkg)

            if on_src and on_tgt:
                classification = "BASELINE"
                excluded_packages.add(pkg)
            elif on_tgt and not on_src:
                classification = "TARGET_ONLY"
            elif on_src and not on_tgt:
                if is_ent:
                    classification = "BASELINE_MISSING_ON_TARGET"
                    excluded_packages.add(pkg)
                else:
                    classification = "CANDIDATE"

            entries.append(BaselineEntry(
                kind="rpm",
                name=pkg,
                on_source=on_src,
                on_target=on_tgt,
                enterprise=is_ent,
                classification=classification
            ))

        # 3. Compare Services
        all_services = src_services | tgt_services
        for svc in sorted(all_services):
            on_src = svc in src_services
            on_tgt = svc in tgt_services
            is_ent = is_enterprise_service(svc)

            if on_src and on_tgt:
                classification = "BASELINE"
                excluded_services.add(svc)
            elif on_tgt and not on_src:
                classification = "TARGET_ONLY"
            elif on_src and not on_tgt:
                if is_ent:
                    classification = "BASELINE_MISSING_ON_TARGET"
                    excluded_services.add(svc)
                else:
                    classification = "CANDIDATE"

            entries.append(BaselineEntry(
                kind="service",
                name=svc,
                on_source=on_src,
                on_target=on_tgt,
                enterprise=is_ent,
                classification=classification
            ))

        return PlatformBaseline(
            entries=entries,
            excluded_paths=excluded_paths,
            excluded_packages=excluded_packages,
            excluded_services=excluded_services
        )
