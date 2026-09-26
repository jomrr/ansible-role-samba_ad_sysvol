# Ansible Role: samba_ad_sysvol

![GitHub](https://img.shields.io/github/license/jomrr/ansible-role-samba_ad_sysvol)
![GitHub last commit](https://img.shields.io/github/last-commit/jomrr/ansible-role-samba_ad_sysvol)
![GitHub issues](https://img.shields.io/github/issues-raw/jomrr/ansible-role-samba_ad_sysvol)
[![dev](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-samba_ad_sysvol/dev.yml?branch=dev&label=dev)](https://github.com/jomrr/ansible-role-samba_ad_sysvol/actions/workflows/dev.yml?query=branch%3Adev)
[![main](https://img.shields.io/github/actions/workflow/status/jomrr/ansible-role-samba_ad_sysvol/main.yml?branch=main&label=main)](https://github.com/jomrr/ansible-role-samba_ad_sysvol/actions/workflows/main.yml?query=branch%3Amain)

Ansible role for pulling SYSVOL between existing Samba AD domain controllers.

## Purpose

Synchronize SYSVOL content to existing Samba AD DCs and reconstruct permissions
from their local AD replicas.

## Scope

### Managed

- A five-minute SYSVOL pull timer, restricted SSH keys, pinned source host keys
  and local ACL reconstruction.
- Removal of owned synchronization resources and restoration of changed SELinux
  booleans.

### Not Managed

- Domain controller provisioning, AD replication, SSH server policy or automatic
  PDC discovery.
- Replication of idmap.ldb, POSIX ACLs, extended attributes or custom file ACLs.

## Requirements

- Existing writable Samba AD DCs; apply this role only to receivers.
- The source must be in the inventory with gathered network and Ed25519 SSH
  host-key facts, reachable through its default IPv4 address, and permit root
  public-key authentication.
- On openSUSE, install rsync documentation files because the package ships
  rrsync there.

## Dependencies

```yaml
collections:
  - name: ansible.posix
    version: '>=2.0.0'
  - name: community.crypto
    version: '>=3.0.0'
  - name: community.general
    version: '>=12.0.0'
  - name: containers.podman
    version: '>=1.20.0'
  - name: jomrr.samba
    version: '>=2.0.0'
```

## Role Variables

### `samba_ad_sysvol_enabled`

Type: `bool`. Required: `false`.

Configure synchronization; false removes this role's service, keys and saved
state.

Default:

```yaml
samba_ad_sysvol_enabled: true
```

### `samba_ad_sysvol_source`

Type: `str`. Required: `false`.

Inventory hostname of the source DC with gathered facts; required when
synchronization is enabled.

## Managed Files

- `/etc/samba/sysvol-pull/`
- `/usr/local/libexec/samba-sysvol-pull`
- `/etc/systemd/system/samba-sysvol-pull.service`
- `/etc/systemd/system/samba-sysvol-pull.timer`
- `/var/lib/samba-sysvol-pull/`

## Check Mode

Supported after an initial successful application.

## Service Behavior

Configuration changes trigger a successful pull before the timer starts.
Subsequent pulls run every five minutes.

## Security Notes

- Each receiver has its own source-address restricted, read-only rrsync key.
  Other root authorizations are preserved.
- File changes and local GPO USNs trigger sysvolreset. Unchanged runs neither
  rewrite ACLs nor generate SYSVOL VFS audit entries.

## Operational Notes

- Edit GPOs on the source, normally the PDC emulator. Update
  samba_ad_sysvol_source in the inventory after a PDC change. The local realm is
  read from smb.conf.
- Disabling synchronization preserves SYSVOL data, unrelated SSH keys and shared
  packages. The previous source must remain reachable to revoke its
  authorization.

## Supported Platforms

| OS Family | Distribution | Version | Container Image |
| --------- | ------------ | ------- | --------------- |
| RedHat | AlmaLinux | latest | [jomrr/molecule-almalinux:latest](https://hub.docker.com/r/jomrr/molecule-almalinux) |
| Debian | Debian | latest | [jomrr/molecule-debian:latest](https://hub.docker.com/r/jomrr/molecule-debian) |
| RedHat | Fedora | latest | [jomrr/molecule-fedora:latest](https://hub.docker.com/r/jomrr/molecule-fedora) |
| Suse | OpenSuse Tumbleweed | latest | [jomrr/molecule-opensuse-tumbleweed:latest](https://hub.docker.com/r/jomrr/molecule-opensuse-tumbleweed) |
| Debian | Ubuntu | latest | [jomrr/molecule-ubuntu:latest](https://hub.docker.com/r/jomrr/molecule-ubuntu) |

## Example Playbook

### Pull SYSVOL on additional DCs

```yaml
---
- name: Gather facts for the source and receivers
  hosts: samba_ad_dcs
  gather_facts: true

- name: Configure SYSVOL receivers
  hosts: samba_ad_receivers
  gather_facts: true
  roles:
    - role: jomrr.samba_ad_sysvol
      samba_ad_sysvol_source: dc1

```

## Author

[Jonas Mauer](https://github.com/jomrr)

## License

This project is licensed under the MIT License.
See [LICENSE](LICENSE) for the full license text.

Copyright (c) 2026 Jonas Mauer.
