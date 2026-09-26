#!/usr/bin/python
"""Exercise SYSVOL content, local ACL reconstruction and quiet repeat transfers."""

DOCUMENTATION = r"""
module: samba_ad_sysvol_test
short_description: Exercise SYSVOL synchronization in the disposable DC fixture
description:
  - Creates and changes a GPO and verifies content and local ACLs on the receiver.
  - Checks unchanged transfers and recovery after an interrupted reset.
options:
  phase:
    description: Fixture operation to perform.
    type: str
    required: true
    choices: [create, rights, files, script, delete, inspect, verify, noop, failed, absent, check]
  password:
    description: Disposable administrator credential for GPO creation and deletion.
    type: str
  expected:
    description: Source GPO metadata and expected content revisions.
    type: dict
    default: {}
author:
  - Jonas Mauer (@jomrr)
"""

EXAMPLES = r"""
- name: SAMBA_AD_SYSVOL | Verify the received SYSVOL fixture
  samba_ad_sysvol_test:
    phase: verify
    expected: "{{ source_gpo }}"
"""

RETURN = r"""
metadata:
  description: Public GPO metadata and local group ID.
  returned: always
  type: dict
ready:
  description: Whether local directory replication matches the expected GPO.
  returned: always
  type: bool
"""

# Ansible requires module documentation before imports.
# pylint: disable=wrong-import-position
import importlib
import re
from pathlib import Path
from typing import Any

from ansible.module_utils.basic import AnsibleModule

# pylint: enable=wrong-import-position

LDB = importlib.import_module("ldb")
SECURITY = importlib.import_module("samba.dcerpc.security")
NDR = importlib.import_module("samba.ndr")

DISPLAY_NAME = "Molecule SYSVOL synchronization"
GROUP_NAME = "molecule-sysvol-filter"
STATE = Path("/var/lib/samba-sysvol-pull/gpo-usn")
AUDIT = Path("/var/log/samba/sysvol_audit.log")
SERVICE = "samba-sysvol-pull.service"


class SysvolFixture:
    """Use Samba's native directory APIs and the role's real systemd unit."""

    def __init__(self, module: Any) -> None:
        self.module = module
        lp = importlib.import_module("samba.param").LoadParm()
        lp.load_default()
        importlib.import_module("samba.samba3.param").get_context().load(lp.configfile)
        self.db = importlib.import_module("samba.samdb").SamDB(
            url=lp.get("private dir") + "/sam.ldb",
            session_info=importlib.import_module("samba.auth").system_session(),
            lp=lp,
        )
        self.base = f"CN=Policies,CN=System,{self.db.domain_dn()}"
        self.realm = lp.get("realm").lower()
        self.root = Path(lp.get("path", "sysvol")) / self.realm
        self.script = self.root / "scripts/molecule-sysvol.cmd"
        self.expected = module.params["expected"]

    @property
    def domain_sid(self) -> Any:
        """Return the local domain identity used to render security descriptors."""
        return SECURITY.dom_sid(self.db.get_domain_sid())

    def run(self, argv: list[str]) -> str:
        """Run a fixture command without placing passwords in arguments."""
        _, output, _ = self.module.run_command(
            argv,
            check_rc=True,
            environ_update={"PASSWD": self.module.params["password"] or ""},
        )
        return str(output).strip()

    def gpo_command(self, verb: str, name: str) -> None:
        """Keep all GPO writes on this pair's source DC."""
        self.run([
            "samba-tool", "gpo", verb, name,
            "-H", f"ldap://dc1.{self.realm}", "-U", "Administrator",
        ])

    def record(self) -> Any:
        """Read only this fixture's GPO from the local replica."""
        result = self.db.search(
            base=self.base, scope=LDB.SCOPE_ONELEVEL,
            expression=f"(displayName={DISPLAY_NAME})",
            attrs=["cn", "nTSecurityDescriptor"],
        )
        return result[0] if result else None

    def group_sid(self) -> str:
        """Resolve the fixture group's Windows identity."""
        result = self.db.search(
            expression=f"(sAMAccountName={GROUP_NAME})", attrs=["objectSid"]
        )
        if not result:
            return ""
        return str(NDR.ndr_unpack(SECURITY.dom_sid, result[0]["objectSid"][0]))

    def metadata(self) -> dict[str, Any]:
        """Read replicated GPO security and the independently allocated Unix ID."""
        record = self.record()
        sid = self.group_sid()
        if record is None or not sid:
            return {}
        descriptor = NDR.ndr_unpack(
            SECURITY.descriptor, record["nTSecurityDescriptor"][0]
        )
        passdb = importlib.import_module("samba.samba3.passdb").PDB(
            "samba_dsdb:" + self.db.url
        )
        local_id, _ = passdb.sid_to_id(SECURITY.dom_sid(sid))
        return {
            "guid": record["cn"][0].decode(),
            "sddl": descriptor.as_sddl(self.domain_sid),
            "sid": sid,
            "gid": int(local_id),
        }

    def set_filter(self, rights: str) -> None:
        """Change only the GPO's replicated DACL, including Apply Group Policy."""
        record = self.record()
        sid = self.group_sid()
        descriptor = NDR.ndr_unpack(
            SECURITY.descriptor, record["nTSecurityDescriptor"][0]
        )
        sddl = re.sub(
            r"\([^()]*;" + re.escape(sid) + r"\)",
            "", descriptor.as_sddl(self.domain_sid),
        )
        dacl, separator, sacl = sddl.partition("S:")
        ace = f"(A;CI;{rights};;;{sid})"
        ace += f"(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;{sid})"
        descriptor = SECURITY.descriptor.from_sddl(
            dacl + ace + separator + sacl, self.domain_sid
        )
        message = LDB.Message()
        message.dn = record.dn
        message["nTSecurityDescriptor"] = LDB.MessageElement(
            NDR.ndr_pack(descriptor), LDB.FLAG_MOD_REPLACE,
            "nTSecurityDescriptor",
        )
        self.db.modify(message, controls=["sd_flags:1:4"])

    def policy_path(self) -> Path:
        """Locate the current GPO's files."""
        return self.root / "Policies" / self.record()["cn"][0].decode()

    def create(self) -> None:
        """Seed a real GPO, security filter and files in both SYSVOL shares."""
        if not self.group_sid():
            self.db.newgroup(GROUP_NAME)
        if self.record() is None:
            self.gpo_command("create", DISPLAY_NAME)
        self.set_filter("RPLCRC")
        machine = self.policy_path() / "Machine"
        machine.mkdir(exist_ok=True)
        (machine / "molecule.txt").write_text("revision-one\n", encoding="utf-8")
        (machine / "remove.txt").write_text("delete this file\n", encoding="utf-8")
        self.script.write_text("script-one\n", encoding="utf-8")
        self.run(["samba-tool", "ntacl", "sysvolreset"])

    def rights(self) -> None:
        """Change AD permissions without changing any content or timestamps."""
        self.set_filter("RPWPCCDCLCLORCWOWDSDDTSW")
        self.run(["samba-tool", "ntacl", "sysvolreset"])

    def files(self) -> None:
        """Change and delete GPO files without changing AD metadata."""
        machine = self.policy_path() / "Machine"
        (machine / "molecule.txt").write_text("revision-two-longer\n", encoding="utf-8")
        (machine / "remove.txt").unlink()
        self.run(["samba-tool", "ntacl", "sysvolreset"])

    def change_script(self) -> None:
        """Trigger a pure NETLOGON transfer for the failed-reset regression."""
        self.script.write_text("script-two-longer\n", encoding="utf-8")
        self.run(["samba-tool", "ntacl", "sysvolreset"])

    def delete(self) -> None:
        """Delete the actual GPO and its SYSVOL directory."""
        self.gpo_command("del", self.record()["cn"][0].decode())

    def ready(self, metadata: dict[str, Any]) -> bool:
        """Wait for DRS independently of the filesystem transfer."""
        return bool(metadata) and all(
            metadata[key] == self.expected[key] for key in ("guid", "sid", "sddl")
        )

    def verify(self) -> None:
        """Check files, independent mappings and Samba's effective GPO ACLs."""
        metadata = self.metadata()
        if not self.ready(metadata):
            raise RuntimeError("GPO replication is incomplete")
        if metadata["gid"] == self.expected["gid"]:
            raise RuntimeError("The fixture must use different local group IDs")
        machine = self.policy_path() / "Machine"
        wanted = self.expected.get("revision", "revision-one") + "\n"
        if (machine / "molecule.txt").read_text(encoding="utf-8") != wanted:
            raise RuntimeError("GPO content was not synchronized")
        wanted_script = self.expected.get("script", "script-one") + "\n"
        if self.script.read_text(encoding="utf-8") != wanted_script:
            raise RuntimeError("NETLOGON content was not synchronized")
        if self.expected.get("removed", False) and (machine / "remove.txt").exists():
            raise RuntimeError("A deleted source file remains on the receiver")
        self.run(["samba-tool", "ntacl", "sysvolcheck"])
        if not STATE.is_file():
            raise RuntimeError("A successful pull did not persist its GPO state")

    def snapshot(self) -> dict[str, Any]:
        """Inspect files directly so the verification itself produces no VFS audit."""
        result: dict[str, Any] = {}
        for path in sorted(self.root.rglob("*")):
            stat = path.lstat()
            result[str(path)] = (stat.st_uid, stat.st_gid, stat.st_mode, stat.st_ctime_ns)
        result["audit"] = AUDIT.read_bytes() if AUDIT.exists() else b""
        return result

    def noop(self) -> None:
        """Two unchanged runs must neither rewrite ACLs nor log VFS operations."""
        # The fixture starts units back-to-back instead of at five-minute intervals.
        self.run(["systemctl", "reset-failed", SERVICE])
        before = self.snapshot()
        for _ in range(2):
            self.run(["systemctl", "start", SERVICE])
            if self.snapshot() != before:
                raise RuntimeError("An unchanged pull rewrote SYSVOL metadata or audit")

    def failed(self) -> None:
        """The transfer completed but its failed reset left no success marker."""
        if self.script.read_text(encoding="utf-8") != "script-two-longer\n":
            raise RuntimeError("The regression must fail after the file transfer")
        if STATE.exists():
            raise RuntimeError("The failed reset retained a misleading success marker")

    def absent(self) -> None:
        """Both replicas and the receiving tree must reflect GPO deletion."""
        if self.record() is not None:
            raise RuntimeError("The deleted GPO remains in AD")
        if (self.root / "Policies" / self.expected["guid"]).exists():
            raise RuntimeError("The deleted GPO remains in SYSVOL")
        self.run(["samba-tool", "ntacl", "sysvolcheck"])


def main() -> None:
    """Dispatch one fixture step and return only non-secret metadata."""
    module = AnsibleModule(
        argument_spec={
            "phase": {"type": "str", "required": True, "choices": [
                "create", "rights", "files", "script", "delete", "inspect",
                "verify", "noop", "failed", "absent", "check",
            ]},
            "password": {"type": "str", "no_log": True},
            "expected": {"type": "dict", "default": {}},
        },
        supports_check_mode=False,
    )
    try:
        fixture = SysvolFixture(module)
        phase = module.params["phase"]
        operations = {
            "create": fixture.create, "rights": fixture.rights,
            "files": fixture.files, "script": fixture.change_script,
            "delete": fixture.delete, "verify": fixture.verify,
            "noop": fixture.noop, "failed": fixture.failed, "absent": fixture.absent,
            "check": lambda: fixture.run(["samba-tool", "ntacl", "sysvolcheck"]),
        }
        if phase in operations:
            operations[phase]()
        metadata = fixture.metadata()
        module.exit_json(
            changed=phase in {"create", "rights", "files", "script", "delete"},
            metadata=metadata,
            ready=fixture.ready(metadata) if fixture.expected else bool(metadata),
        )
    except (RuntimeError, OSError, ValueError) as error:
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
