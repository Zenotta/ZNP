# Instruction to generate:
 * src/bin/dbs_v_0_3_0_upgraded.tar.gz
 * src/bin/dbs_v_0_4_0_with_old.tar.gz
 * src/upgrade/tests_last_version_db.rs

## In a separate clone of znp and noam:
 * checkout ZNP at tag v1.1.0
 * checkout NAOM at commit ID 272d5814
 * Make sure znp cargo.toml point to corresponding naom

## Generate database and snapshots in v0.4.0 clone

These instructions will be easier to follow with 5 tabs ready to run the following:
 * `cargo build --bins --release`
 * `rm -rf src/db/db/test.* src/wallet/wallet/test.*; tar -xzf src/bin/dbs_v_0_3_0_with_old.tar.gz`
 * `target/release/upgrade --config=src/bin/node_settings_upgraded.toml --type=all --processing=upgrade --passphrase=TestPassword`
 * `tar -czf src/bin/dbs_v_0_3_0_upgraded.tar.gz src/db/db src/wallet/wallet`

 Then:
 * `echo 12 > shutdown_coordinated`
 * `rm -rf src/db/db/test.* src/wallet/wallet/test.*; tar -xzf src/bin/dbs_v_0_3_0_upgraded.tar.gz ; src/bin/node_settings_upgraded_run.sh set_log debug debug debug debug`
 * Wait for shutdown.
 * `tar -czf src/bin/dbs_v_0_4_0_with_old.tar.gz src/db/db src/wallet/wallet`

## Add snapshot to repo

Copy the snapshots to V4 ZNP repo to:
 * src/bin/dbs_v_0_4_0_with_old.tar.gz

Update rust dumps:

```
rm -rf src/db/db/test.* src/wallet/wallet/test.*; tar -xzf src/bin/dbs_v_0_4_0_with_old.tar.gz
target/release/upgrade --config=src/bin/node_settings_upgraded.toml --type all --processing read > src/upgrade/tests_last_version_db.rs
```
