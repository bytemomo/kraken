# FILE SYNTAX

This file define the syntax and explain each field of the campaign and attack trees
yaml files.

## Campaign

- `id`, `name` and `version` are not essential to the run, they are used to
  describe the campaign.
- `type` switches the execution mode. The default `network` mode performs
  discovery via the scanner and then runs each module against every classified
  target. The `fuzz` mode skips scanning entirely and executes each module as a
  stand-alone task, which is useful for grey/white-box fuzzers that only need
  to emit findings on stdout.
- runner: contains every option to set the EXECUTION phase of the Kraken. This phase
  handles the life cycle of the execution of each module.
    1. global_timeout: timeout for modules, if the module does not specify its
       own or this one is bigger then the global one is used.
    2. max_parallel_targets: number of parallel step that can be executed, the
       Kraken executable will parallelize steps on different targets (i.e. two
       steps on the same `host:port` will NEVER be executed on parallel).

- scanner: Configuration options for Kraken's **SCANNER** phase, which discovers
  and classifies targets. Kraken uses `nmap` under the hood, and many settings
  mirror `nmap` behavior.
    1. open_only: Report only open ports.
    2. skip_host_discovery: Skip the host discovery step (do not attempt to
       find live hosts).
    3. enable_udp: Also scan UDP ports.
    4. service_detect: Enable service/version detection and fingerprinting.
       Setting this to `false` disables service detection, which reduces classification
       accuracy. When enabled, it supports two mutually exclusive modes:
       `version_all` or `version_light`.
    5. min_rate: Enforce a minimum probes-per-second rate for the scan (useful to
       control throughput).
    6. timeout: Maximum time to wait for probes or host responses before considering
       them timed out.
    7. timing: Controls scan aggressiveness (how quickly probes are sent, parallelism,
       and retry/backoff behavior). Values map to nmap timing templates:
       `paranoid = T0`, `sneaky = T1`, `polite = T2`, `normal = T3` (default),
       `aggressive = T4`, `insane = T5`.
    8. ports: List of ports to target. If empty, the scanner will use the standard
       port set.

- attack_trees_def_path: relative path to load from the attack tree definition file.

- steps: TODO. Modules can be executed via ABI/GRPC/CLI or through `exec.docker`
  to run CLI/fuzz modules inside a container. Docker-backed modules must emit a
  JSON `RunResult` on stdout; Kraken mounts the output directory into the
  container when it is available so artifacts can be persisted.

## Attack Trees

Attack tree definitions for IoT campaigns.

- type: LEAF | AND | OR
    1. AND: if all the children are TRUE then also this node is TRUE
    2. OR: at least one node from the children has to be TRUE to activate the node
    3. LEAF: to be true the findings have to match in one of the ways the specified
       in the finding_mode field

- findings: list
    1. list of finding names that the modules will write in the results when that
       module find a certain finding. They need to match with the modules' one
       and the name is case sensitive

- finding_mode: any | all | threshold
    1. any: if there is one match in the finding ids and the findings found after
       the run then the node is true.
    2. all: only if ALL the finding ids are found in the run then the node is true.
    3. trheshold: if the number of asserted finding id is > finding_threshold
       then the node is true.

- finding_threashold: int
    1. number of findings that needs to be found in the run to activate the node
