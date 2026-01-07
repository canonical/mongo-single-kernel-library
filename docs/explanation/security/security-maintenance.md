(security-maintenance)=
# Security maintenance

Charmed MongoDB follows a defined security maintenance and life-cycle policy to help users understand which versions receive security updates and for how long.

## Supported versions

Security updates are provided only for the following **actively supported channels**:

| Charm channel | Upstream MongoDB version | Base | End of Life (EoL) |
|--------------|--------------------------|------|------------------|
| `6/stable`   | MongoDB 6.0              | Ubuntu 22.04 LTS (jammy) | 2033 |
| `8/stable`   | MongoDB 8.0              | Ubuntu 24.04 LTS (noble) | Oct 2035 |

- Only the channels listed above receive security patches and updates.
- Support timelines are aligned with upstream MongoDB maintenance policies and the underlying Ubuntu LTS base.

### End of Life (EoL)

Once a channel reaches its End of Life:
- No further security updates or bug fixes will be provided.
- Users must upgrade to a supported channel to continue receiving security maintenance.

Operators are strongly encouraged to plan upgrades ahead of the EoL date to avoid running unsupported software.

### User responsibilities

Users are responsible for:
- Tracking the support status of the deployed charm channel.
- Applying updates and upgrades in a timely manner.
- Monitoring official Charmed MongoDB and Canonical announcements regarding security maintenance and EoL timelines.

## Reporting vulnerabilities

Security issues in Charmed MongoDB should be reported responsibly to ensure they are addressed quickly and safely.
Do not report security vulnerabilities through public issue trackers.

Instead, follow the guidance in the security policy:

- [Charmed MongoDB operator](https://github.com/canonical/mongodb-k8s-operator/blob/8/edge/SECURITY.md)
- [Charmed MongoDB K8s operator](https://github.com/canonical/mongodb-operator/blob/8/edge/SECURITY.md)
- [Charmed Mongos operator](https://github.com/canonical/mongos-k8s-operator/blob/8/edge/SECURITY.md)
- [Charmed Mongos K8s operator](https://github.com/canonical/mongos-operator/blob/8/edge/SECURITY.md)
- [Mongo Charms Single Kernel library](https://github.com/canonical/mongo-single-kernel-library/blob/8/edge/SECURITY.md)

Security reports should comply with the [Ubuntu Disclosure Policy](https://ubuntu.com/security/disclosure-policy), which outlines responsible disclosure practices and expectations.
