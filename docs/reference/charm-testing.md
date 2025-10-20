(charm-testing)=
# Charm testing

Charmed MongoDB development supports software unit tests, integration tests, and performance tests.

## Unit tests

See [CONTRIBUTING.md](https://github.com/canonical/mongo-single-kernel-library/blob/6/edge/CONTRIBUTING.md#testing) and follow the `tox` examples

## Integration tests

Integration test coverage is quite rich in MongoDB charms. When it comes to complex features and HA (High Availability), each test serves as an integration as well as a smoke test with continuous writes routines being perpetually ran in parallel of whatever operation the test is involved in. 

These continuous writes ensure the availability of the service under different conditions. These tests make use of the following fixture:
-  `continuous_writes`: creates a replicated collection and continuously stores data into it.

After each test completes, the collection gets deleted.

## Performance tests

See the following guides (external links):
* MongoDB VM: [Performance testing for VM charm](https://discourse.charmhub.io/t/how-to-charmed-mongodb-performance-testing-for-vm-charm/13942)
* MongoDB K8s: [Performance testing for K8s charm](https://discourse.charmhub.io/t/how-to-charmed-mongodb-performance-testing-for-k8s-charm/13966)
