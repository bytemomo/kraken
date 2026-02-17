# Testing Guide

The instructions below explain how to run test suites, including privileged tests
for EtherCAT and raw IP conduits.

## Use Justfile

```sh
just test
```

## Manual

- For privileged datalink/raw IP tests: a root shell (`sudo`) and the `ip` command (for veth pairs).

- Standard unit tests (no elevated privileges):

    ```bash
    $ go test ./kraken/... -v
    ```

- How to compile tests for testing that requires `root` privileges

    ```bash
    # From repo root
    $ go test -c ./trident/... -o ./dist/trident_tests
    $ ls ./dist/trident_tests
    adapters.test  datalink.test  network.test  tls.test  transport.test

    $ go test -c ./kraken/... -o ./dist/kraken_tests
    $ ls ./dist/kraken_tests
    domain.test  ethercat.test  native.test  protocol.test	runner.test  scanner.test  testutil.test  transport.test  vendor.test  yamlconfig.test
    ```

- To run tests that requires privileges:

    ```bash
    sudo ./dist/<package>_tests/<test_requiring_sudo>
    ```
