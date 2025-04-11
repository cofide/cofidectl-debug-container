# cofidectl debug container

This is a debug container that is used by [`cofidectl`](https://www.github.com/cofide/cofidectl) to discover the SPIFFE SVID and trust bundle issued to a workload, as part of the `cofidectl workload status` command. It helps to debug a running workload in a cluster and ensure it's identity is as intended.

Cofide provide a ready-made container image used by `cofidectl` but you may wish to [build](#build) your own.

## Prerequisites

Building a `cofidectl-debug-container` binary requires:

* [Go 1.23 toolchain](https://golang.org/doc/install)
* [`just`](https://github.com/casey/just) as a command runner
* [`ko`](https://github.com/ko-build/ko) to build container images

## Build

To run the unit tests and build the `cofidectl-debug-container` binary:

```sh
just build-release
```

## How it works

With `cofidectl`, this container is executed in-cluster as a Kubernetes [ephemeral container](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/). The Go application interfaces with the [SPIFFE Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md) to obtain the SPIFFE SVID and trust bundle issued to a workload. `cofidectl` prints this to the console - for example:

```
./cofidectl workload status foo --namespace demo --pod-name ping-pong-client-f6f6495b5-zb9bd --trust-zone cofide-a
✅ Complete: Successfully executed emphemeral container in ping-pong-client-f6f6495b5-zb9bd

Trust bundles received
* spiffe://cofide-a.test
    Certificate "22:FA:3D:F3:D5:B7:FC:47:5E:AA:A1:7A:66:A6:03:2D:B0:90:E3:30:A7:7C:9F:3C:F0:33:18:78:3A:41:62:EB"
    is a CA certificate
    valid from "2024-11-22T04:15:53Z" to "2024-11-22T16:16:03Z"
    Subject: SERIALNUMBER=134874419949172333976462662483560844916,CN=example.org,O=Example,C=ARPA
    DNS names: spiffe://cofide-a.test
    Signature algorithm: SHA256-RSA
    Issuer: SERIALNUMBER=134874419949172333976462662483560844916,CN=example.org,O=Example,C=ARPA

SVIDs received
* spiffe://cofide-a.test/ns/demo/sa/ping-pong-client
    Certificate "4D:FA:5B:56:EC:B4:73:FF:24:9C:2D:E6:DE:AC:41:3B:0B:BE:42:B8:2F:E9:2C:71:87:FF:BD:E0:C3:C8:9D:E4"
    valid from "2024-11-22T09:10:10Z" to "2024-11-22T13:10:20Z"
    Subject: O=SPIRE,C=US
    DNS names: spiffe://cofide-a.test/ns/demo/sa/ping-pong-client
    Signature algorithm: SHA256-RSA
    Issuer: SERIALNUMBER=134874419949172333976462662483560844916,CN=example.org,O=Example,C=ARPA
    SVID verified against trust bundle
```
