<!--
Release notes for Charmed MongoDB (VM), revision 406 (proposed — see TODOs).

Generated 2026-10-13 from canonical/mongo-single-kernel-library, branch 8/edge
(local branch `auto-release-notes-2`, HEAD f30c7fa674, same commit as
origin/8/edge).

Sources and inferences:
- Repository: canonical/mongo-single-kernel-library (the shared single-kernel
  library repo for the Charmed MongoDB VM and K8s charms).
- Product: Charmed MongoDB (VM) — per docs/reference/release-notes/vm/.
- Track: 8 (docs default branch is 8/edge; docs/index.md links Charmhub
  channel 8/edge).
- from-ref: b3afc9e46f — the commit that added the previous VM release notes
  (docs/reference/release-notes/vm/revision-262.md, "fix: release notes
  (#199)", 2026-01-16). The range is exclusive of from-ref: this document
  covers everything after it, up to HEAD f30c7fa674 (2026-10-12), 109 commits.
- Title revision: 406 — per the release owner's instruction, the number must
  not be lower than the biggest revision already published on Charmhub.
  canonical/mongodb-operator's latest tag is rev405 (peeled commit
  13b419a11f = its 8/edge HEAD, 2026-10-09), and that charm build pins
  mongo-charms-single-kernel v1.8.72 (library commit 6c83294ab0), which is 4
  commits behind this document's HEAD — so rev405 does NOT ship these changes
  and this document describes the NEXT release: 406. Mongos: latest tag
  rev216 (peeled 41a0fcf7cd = its 8/edge HEAD, pins the same v1.8.72), so 217
  is proposed.
  TODO (release owner): confirm the final published revision numbers before
  publishing — charm revisions are allocated per architecture (pairs), so the
  published numbers may differ from these proposals.
- Scope: VM charms only (MongoDB + Mongos), confirmed by the release owner.
  The K8s charms (mongodb-k8s, mongos-k8s — documented separately under
  docs/reference/release-notes/k8s/, latest revision 114) are NOT covered.
  The library is shared, so some entries below touch K8s code too; they are
  kept because the library is the released artefact.
- Auto-sort: RAN (explicitly enabled by the release owner), but it moved NO
  entries: every entry in this range carries a neutral conventional-commit
  prefix (`patch:`, `patch():`, `patch(scope):`) or none, which never
  triggers a move. The single `fix:`-prefixed entry (PR #278 "fix: ci
  maintenance") targets CI tooling, so per the infrastructure-only exception
  it stays in "Other improvements" and is flagged here. Entries whose titles
  start with fix verbs but carry a neutral prefix (PR #217 "fix previous tag
  retrieval...", PR #224, PR #343, PR #344, PR #367, PR #369, PR #375, PR
  #382, PR #400, PR #402, PR #405, PR #419, PR #421, PR #424, PR #432) are
  settled by their neutral prefix and stay put unflagged.
- Categorisation note: the builder's label mapping put all 109 entries in
  "Other improvements" (no PRs in this range carry DA186 category labels).
  Plainly-feature-like entries (e.g. PR #258 encryption at rest, PR #218 GCS
  backup, PR #244 Juju spaces, PR #321 LDAP self-healing, PR #319 async
  restarts) were NOT moved because auto-sort keys only off explicit signals
  (`feat:` etc.), and guessing from prose is deliberately out of scope. The
  release owner may want to promote the headline features into a Features
  section by hand.
- Typos corrected in PR titles (spelling only, meaning untouched):
  "syncrhonize" → "synchronize" (PR #330), "depencies" → "dependencies"
  (PR #481).
- Compatibility sources: tests/charms/mongodb_test_charm/refresh_versions.toml
  (workload 8.0.28; snap revisions x86_64=320, aarch64=319),
  docs/reference/system-requirements.md (Juju 3.0+; previous release notes
  say minimum 3.6 LTS), previous VM revision-262.md compatibility table.
  TODO (release owner): verify the snap component versions below (Exporter,
  mongosh, PBM) against the shipped charmed-mongodb snap — the snap repo's
  8/edge snap/snapcraft.yaml still shows version "8.0.10-4" and does not pin
  per-component versions, while the library pins workload 8.0.28; the values
  below follow the library's refresh_versions.toml and the previous release
  notes where unchanged.
- Known issues carried over verbatim from revision-262.md.
- The existing draft of vm/revision-263.md on branch `auto-release-notes`
  was ignored per the release owner's instruction ("work independently").
- Nothing was pushed or published — this file exists only in this local
  repository.
-->

(revision-406)=

# Revision 406

<sub>13 October 2026</sub>

This release of Charmed MongoDB and Mongos 8 for VM brings encryption at rest, Juju spaces support, GCS backup support, LDAP self-healing, rolling operations improvements, and a workload bump to MongoDB 8.0.28.

| Charm   | Revision | Charmhub track                                             |
|---------|----------|------------------------------------------------------------|
| MongoDB | 406      | [`8/stable`](https://charmhub.io/mongodb?channel=8/stable) |
| Mongos  | 217      | [`8/stable`](https://charmhub.io/mongos?channel=8/stable) |

[Charmhub](https://charmhub.io/mongodb) | [Deployment guides](how-to-deploy) | [Upgrade guides](how-to-upgrade) | [System requirements](system-requirements)

## Other improvements

This release includes the following changes to the shared single-kernel library:

* Improve CI to build and test both architectures ([PR #203](https://github.com/canonical/mongo-single-kernel-library/pull/203))
* Update test charms and integration tests ([PR #206](https://github.com/canonical/mongo-single-kernel-library/pull/206))
* Set IPv4 TCP `Keepalive` time ([PR #207](https://github.com/canonical/mongo-single-kernel-library/pull/207))
* Improve CI stability ([PR #204](https://github.com/canonical/mongo-single-kernel-library/pull/204))
* Improve the PR generated by the bump `mongo-single-kernel-library` in charms workflow ([PR #188](https://github.com/canonical/mongo-single-kernel-library/pull/188))
* Handle more error cases ([PR #211](https://github.com/canonical/mongo-single-kernel-library/pull/211))
* Bump rock and snap ([PR #215](https://github.com/canonical/mongo-single-kernel-library/pull/215))
* Remove duplication on PBM CA certificate storage ([PR #216](https://github.com/canonical/mongo-single-kernel-library/pull/216))
* Bump `charm-libs` ([PR #219](https://github.com/canonical/mongo-single-kernel-library/pull/219))
* Update spread config to test both architectures ([PR #210](https://github.com/canonical/mongo-single-kernel-library/pull/210))
* Fix previous tag retrieval in the bump `mongo-single-kernel-library` automated workflow ([PR #217](https://github.com/canonical/mongo-single-kernel-library/pull/217))
* Nightly run and Allure report ([PR #221](https://github.com/canonical/mongo-single-kernel-library/pull/221))
* GCS Backup support ([PR #218](https://github.com/canonical/mongo-single-kernel-library/pull/218))
* Add `apt update` ([PR #232](https://github.com/canonical/mongo-single-kernel-library/pull/232))
* Fix tag content retrieval in the bump single kernel workflow ([PR #224](https://github.com/canonical/mongo-single-kernel-library/pull/224))
* CI: wait for the PyPI release to be found before triggering the `mongo-single-kernel-library` bumping workflow ([PR #233](https://github.com/canonical/mongo-single-kernel-library/pull/233))
* Create a summary for the bump charms action ([PR #234](https://github.com/canonical/mongo-single-kernel-library/pull/234))
* CI: wait for poetry to find the newly released lib version in the bump `mongo-single-kernel-library` workflow ([PR #236](https://github.com/canonical/mongo-single-kernel-library/pull/236))
* Send CA certificate to clients ([PR #241](https://github.com/canonical/mongo-single-kernel-library/pull/241))
* Event-agnostic backup/restore checks ([PR #235](https://github.com/canonical/mongo-single-kernel-library/pull/235))
* Shard integration and backups stability ([PR #246](https://github.com/canonical/mongo-single-kernel-library/pull/246))
* Switch back to GH runners for most of the tests ([PR #247](https://github.com/canonical/mongo-single-kernel-library/pull/247))
* Select correct tests ([PR #251](https://github.com/canonical/mongo-single-kernel-library/pull/251))
* Use new spread path ([PR #261](https://github.com/canonical/mongo-single-kernel-library/pull/261))
* MongoDB Juju spaces support ([PR #244](https://github.com/canonical/mongo-single-kernel-library/pull/244))
* Use 22.04 runners ([PR #272](https://github.com/canonical/mongo-single-kernel-library/pull/272))
* Update documentation starter pack version (8) ([PR #279](https://github.com/canonical/mongo-single-kernel-library/pull/279))
* Backups documentation updated ([PR #271](https://github.com/canonical/mongo-single-kernel-library/pull/271))
* CI maintenance ([PR #278](https://github.com/canonical/mongo-single-kernel-library/pull/278))
* Update documentation landing pages (8) ([PR #281](https://github.com/canonical/mongo-single-kernel-library/pull/281))
* `allowConnectionsWithoutCertificates` ([PR #287](https://github.com/canonical/mongo-single-kernel-library/pull/287))
* MongoDB Encryption At Rest ([PR #258](https://github.com/canonical/mongo-single-kernel-library/pull/258))
* Scale-up-down test ([PR #316](https://github.com/canonical/mongo-single-kernel-library/pull/316))
* Race condition handling + secret events ([PR #315](https://github.com/canonical/mongo-single-kernel-library/pull/315))
* Documentation for encryption at rest ([PR #273](https://github.com/canonical/mongo-single-kernel-library/pull/273))
* CI Green ([PR #317](https://github.com/canonical/mongo-single-kernel-library/pull/317))
* Workflow to call Airflow ([PR #298](https://github.com/canonical/mongo-single-kernel-library/pull/298))
* Self healing for LDAP ([PR #321](https://github.com/canonical/mongo-single-kernel-library/pull/321))
* Use rolling ops during `teardown` ([PR #318](https://github.com/canonical/mongo-single-kernel-library/pull/318))
* Release testing ([PR #290](https://github.com/canonical/mongo-single-kernel-library/pull/290))
* Update dependencies in `pyproject.toml` ([PR #328](https://github.com/canonical/mongo-single-kernel-library/pull/328))
* Run `check_pr` also on synchronize so it always shows up ([PR #330](https://github.com/canonical/mongo-single-kernel-library/pull/330))
* Add `async` restarts using `charmlibs-rollingops` ([PR #319](https://github.com/canonical/mongo-single-kernel-library/pull/319))
* Bump microk8s in CI to 1.35-strict ([PR #334](https://github.com/canonical/mongo-single-kernel-library/pull/334))
* Bump dependencies ([PR #338](https://github.com/canonical/mongo-single-kernel-library/pull/338))
* Add rolling operations documentation ([PR #332](https://github.com/canonical/mongo-single-kernel-library/pull/332))
* Improve rolling operations integration test ([PR #337](https://github.com/canonical/mongo-single-kernel-library/pull/337))
* Fix release job permissions ([PR #343](https://github.com/canonical/mongo-single-kernel-library/pull/343))
* Fix CI permissions in release workflow ([PR #344](https://github.com/canonical/mongo-single-kernel-library/pull/344))
* MongoDB 8.0.10-4 ([PR #348](https://github.com/canonical/mongo-single-kernel-library/pull/348))
* Don't request certs for `unix` socket ([PR #351](https://github.com/canonical/mongo-single-kernel-library/pull/351))
* Fix docs references and broken links ([PR #367](https://github.com/canonical/mongo-single-kernel-library/pull/367))
* Fix broken reference to the rolling-ops title ([PR #369](https://github.com/canonical/mongo-single-kernel-library/pull/369))
* Migrate docs domain to `canonical.com/data/mongodb/docs` (8) ([PR #377](https://github.com/canonical/mongo-single-kernel-library/pull/377))
* Add tenacity when reaching the snap store to get the `charmed-mongodb` snap ([PR #373](https://github.com/canonical/mongo-single-kernel-library/pull/373))
* Bug fixing and stabilization ([PR #353](https://github.com/canonical/mongo-single-kernel-library/pull/353))
* Fix IP restrictions for replica sets in different subnets (AWS) ([PR #375](https://github.com/canonical/mongo-single-kernel-library/pull/375))
* Update cluster IP source allowlist in sharded cluster (AWS) ([PR #382](https://github.com/canonical/mongo-single-kernel-library/pull/382))
* MongoDB 8 Build and release newest versions of artifacts ([PR #392](https://github.com/canonical/mongo-single-kernel-library/pull/392))
* Use `json` output for backups ([PR #395](https://github.com/canonical/mongo-single-kernel-library/pull/395))
* Repository maintenance and dependencies care ([PR #397](https://github.com/canonical/mongo-single-kernel-library/pull/397))
* Refine encryption at rest test ([PR #396](https://github.com/canonical/mongo-single-kernel-library/pull/396))
* Workflow upgrades ([PR #404](https://github.com/canonical/mongo-single-kernel-library/pull/404))
* Improve HA test for `db_step_down` ([PR #407](https://github.com/canonical/mongo-single-kernel-library/pull/407))
* X-model issue ([PR #393](https://github.com/canonical/mongo-single-kernel-library/pull/393))
* Workflow ([PR #413](https://github.com/canonical/mongo-single-kernel-library/pull/413))
* Release Workflow permissions ([PR #415](https://github.com/canonical/mongo-single-kernel-library/pull/415))
* Fix `has_file` function to check on every unit instead of only checking the leader ([PR #405](https://github.com/canonical/mongo-single-kernel-library/pull/405))
* Better backup configuration ([PR #406](https://github.com/canonical/mongo-single-kernel-library/pull/406))
* Release workflow version number ([PR #417](https://github.com/canonical/mongo-single-kernel-library/pull/417))
* Fix `/tmp` permissions for AWS EKS deployments ([PR #400](https://github.com/canonical/mongo-single-kernel-library/pull/400))
* Fix install hook failure for VM deployment in AWS ([PR #402](https://github.com/canonical/mongo-single-kernel-library/pull/402))
* MongoDB 8.0.28 and PBM Agent log file ([PR #414](https://github.com/canonical/mongo-single-kernel-library/pull/414))
* Properly template SSH key secret ([PR #418](https://github.com/canonical/mongo-single-kernel-library/pull/418))
* Fix the bump single kernel workflow ([PR #419](https://github.com/canonical/mongo-single-kernel-library/pull/419))
* Catch deferrable error in relation joined event ([PR #421](https://github.com/canonical/mongo-single-kernel-library/pull/421))
* Fix config-server start loop ([PR #424](https://github.com/canonical/mongo-single-kernel-library/pull/424))
* Fix `zizmor` ([PR #432](https://github.com/canonical/mongo-single-kernel-library/pull/432))
* Documentation: encryption at rest and Terraform deploy ([PR #430](https://github.com/canonical/mongo-single-kernel-library/pull/430))
* Refactor Mongos / Config-Server relation ([PR #416](https://github.com/canonical/mongo-single-kernel-library/pull/416))
* Catch `PrematureDataAccessError` exception when propagating CA secrets ([PR #434](https://github.com/canonical/mongo-single-kernel-library/pull/434))
* Documentation: add Juju spaces ([PR #440](https://github.com/canonical/mongo-single-kernel-library/pull/440))
* Documentation: add caution block about Juju spaces on VM charms only ([PR #450](https://github.com/canonical/mongo-single-kernel-library/pull/450))
* Adjust FQDN usage + X-model fixes ([PR #436](https://github.com/canonical/mongo-single-kernel-library/pull/436))
* Migrate first tests to Jubilant ([PR #451](https://github.com/canonical/mongo-single-kernel-library/pull/451))
* Error handling and code fixes for canonical K8s ([PR #456](https://github.com/canonical/mongo-single-kernel-library/pull/456))
* Do not raise on error for `test_pre_refresh_check` ([PR #480](https://github.com/canonical/mongo-single-kernel-library/pull/480))
* Raise on `mongos-k8s` missing trust ([PR #478](https://github.com/canonical/mongo-single-kernel-library/pull/478))
* `test_metrics.py` ([PR #457](https://github.com/canonical/mongo-single-kernel-library/pull/457))
* `test_charm_invalid_config.py` ([PR #459](https://github.com/canonical/mongo-single-kernel-library/pull/459))
* `test_teardown.py` ([PR #460](https://github.com/canonical/mongo-single-kernel-library/pull/460))
* Reduce load on CI ([PR #483](https://github.com/canonical/mongo-single-kernel-library/pull/483))
* Report status upon missing workload ([PR #488](https://github.com/canonical/mongo-single-kernel-library/pull/488))
* Move to canonical K8s ([PR #441](https://github.com/canonical/mongo-single-kernel-library/pull/441))
* Bump dependencies (`charmlibs` rolling ops, `charmlibs` snap, etcd, ...) ([PR #481](https://github.com/canonical/mongo-single-kernel-library/pull/481))
* Update Sphinx tooling (8) ([PR #492](https://github.com/canonical/mongo-single-kernel-library/pull/492))
* `test_sharding.py` ([PR #463](https://github.com/canonical/mongo-single-kernel-library/pull/463))
* `test_sharding_rollingops.py` ([PR #464](https://github.com/canonical/mongo-single-kernel-library/pull/464))
* CI: disable `ci-quick` on `pull_request` ([PR #497](https://github.com/canonical/mongo-single-kernel-library/pull/497))
* `mongodb/tls/test_*.py` ([PR #479](https://github.com/canonical/mongo-single-kernel-library/pull/479))
* Remove `clusterIpSourceAllowlist` and `AuthRestrictions` for K8s ([PR #491](https://github.com/canonical/mongo-single-kernel-library/pull/491))
* `ldap/test_*.py` ([PR #486](https://github.com/canonical/mongo-single-kernel-library/pull/486))
* `encryption/test_*.py` ([PR #489](https://github.com/canonical/mongo-single-kernel-library/pull/489))
* Backups tests ([PR #495](https://github.com/canonical/mongo-single-kernel-library/pull/495))
* Bump rolling operations library ([PR #508](https://github.com/canonical/mongo-single-kernel-library/pull/508))
* Spaces tests ([PR #496](https://github.com/canonical/mongo-single-kernel-library/pull/496))
* HA tests ([PR #499](https://github.com/canonical/mongo-single-kernel-library/pull/499))
* Relation tests ([PR #500](https://github.com/canonical/mongo-single-kernel-library/pull/500))
* Add metadata to docs pages ([PR #501](https://github.com/canonical/mongo-single-kernel-library/pull/501))

## Known issues and limitations

* Restores on backups with old passwords will leave clients / operator user locked out of the DB.
* Sharding cluster cannot drain jumbo chunks - draining jumbo chunks [requires manual intervention](https://www.mongodb.com/docs/manual/tutorial/clear-jumbo-flag/)

## Compatibility & software contents

**Minimum Juju version**: 3.6 LTS

See {ref}`system-requirements` for more information about software and hardware prerequisites.

This charm is based on the Canonical [charmed-mongodb-snap](https://github.com/canonical/charmed-mongodb-snap). It packages:

* Percona Server for MongoDB `v8.0.28`
* MongoDB Exporter `v0.47.1`
* mongosh `v2.5.5`
* Percona Backup for MongoDB `v2.10.0`

## Join the community

Charmed MongoDB is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

* Check our [Code of Conduct](https://ubuntu.com/community/ethos/code-of-conduct)
* Raise software issues or feature requests in [GitHub](https://github.com/canonical/mongo-single-kernel-library/issues)
* Meet the community and chat with us on [Matrix](https://matrix.to/#/#charmhub-data-platform:ubuntu.com)
* [Contribute](https://github.com/canonical/mongo-single-kernel-library/blob/8/edge/CONTRIBUTING.md)