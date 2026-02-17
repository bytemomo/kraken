# 🦑 Kraken System Requisites

## Architecture Overview

![architecture](./architecture.svg)

---

## 1. High-Level Requirements

### 1.1 Core Functionality

- **HL-F1** --- Kraken shall execute security assessment campaigns against specified network and industrial targets.
- **HL-F2** --- Kraken shall discover and scan network targets (host:port) and industrial targets (EtherCAT slaves) to identify services and potential vulnerabilities.
- **HL-F3** --- Kraken shall aggregate results from its components and generate reports in human-readable and machine-readable formats.

### 1.2 User Interaction

- **HL-U1** --- Kraken shall provide a command-line interface (CLI) for campaign execution and configuration.
- **HL-U2** --- _(Future)_ Kraken should provide a web-based graphical interface for real-time monitoring and control of campaigns. **Status: Not implemented.**
- **HL-U3** --- Campaigns shall be defined in a structured format (e.g., YAML) that specifies modules and targets.

### 1.3 System Qualities

- **HL-Q1** --- Kraken shall be delivered as a single, fast, and lightweight binary executable (e.g., final binary size < 50MB).
- **HL-Q2** --- The system shall be modular, with clear separation of concerns between its subsystems.
- **HL-Q3** --- The system shall be resilient, with a recovery mechanism to handle module crashes without halting the entire campaign.
- **HL-Q4** --- The system shall be performant, executing modules concurrently to minimize campaign duration.
- **HL-Q5** --- Kraken shall be extensible through modules to support various transport and network protocols.

---

## 2. Low-Level Requirements

### 2.1 CLI Component (KRK-CLI)

#### 2.1.1 Functional Requirements

- **KRK-CLI-F1** --- The CLI shall accept a `--campaign` argument to specify the path to a campaign file.
- **KRK-CLI-F2** --- The CLI shall accept an optional `--cidrs` argument to specify target hosts/networks, which can also be defined within the campaign file.
- **KRK-CLI-F3** --- The CLI shall accept an `--out` argument to specify the output directory for campaign results (defaulting to `./results`).
- **KRK-CLI-F4** --- The CLI shall provide a `--help` command to display usage information.
- **KRK-CLI-F5** --- The CLI shall provide a command to list all registered modules and their capabilities (e.g., `kraken --list-modules`).

### 2.2 Runner Component (KRK-RUN)

#### 2.2.1 Architectural Requirements

- **KRK-RUN-A1** --- The Runner shall be responsible for orchestrating the execution of modules as defined in a campaign.
- **KRK-RUN-A2** --- The Runner shall provide an internal interface for module scheduling, execution, and lifecycle management.
- **KRK-RUN-A3** --- The Runner shall isolate each module execution to prevent cross-failure.

#### 2.2.2 Functional Requirements

- **KRK-RUN-F1** --- The Runner shall execute modules serially for any single target, and in parallel across different targets.
- **KRK-RUN-F2** --- The Runner shall support a configurable maximum number of parallel executions.
- **KRK-RUN-F3** --- The Runner shall be configurable from the campaign YAML file.
- **KRK-RUN-F4** --- The Runner shall collect module outputs for the Reporter.
- **KRK-RUN-F5** --- The Runner should handle configurable retry and timeout logic during module execution.
- **KRK-RUN-F6** --- The Runner shall produce structured logs for every module execution.

#### 2.2.3 Non-Functional Requirements

- **KRK-RUN-N1** --- The Runner should efficiently use system resources during concurrent execution.
- **KRK-RUN-N2** --- The Runner should ensure stability under high concurrency.
- **KRK-RUN-N4** --- The Runner should recover gracefully from transient system or network errors.
- **KRK-RUN-N5** --- The Runner shall not crash if an individual module crashes.

---

### 2.3 Scanner Component (KRK-SCN)

#### 2.3.1 Architectural Requirements

- **KRK-SCN-A1** --- The Scanner shall serve as Kraken's discovery subsystem.
- **KRK-SCN-A2** --- The Scanner shall integrate with Nmap for IP-layer discovery and scanning.
- **KRK-SCN-A3** --- The Scanner shall expose its results to the Runner and Reporter through a standardized data schema.
- **KRK-SCN-A4** --- The Scanner shall support multiple scanner types (nmap, ethercat) in a single campaign.
- **KRK-SCN-A5** --- The Scanner shall integrate with EtherCAT for Layer 2 industrial device enumeration.

#### 2.3.2 Functional Requirements

- **KRK-SCN-F1** --- The Scanner shall perform network reconnaissance.
- **KRK-SCN-F2** --- The Scanner shall use Nmap for IP-layer scanning (TCP/UDP ports).
- **KRK-SCN-F3** --- The Scanner shall discover live hosts and open ports/services.
- **KRK-SCN-F4** --- The Scanner shall assign classification tags to identified targets.
- **KRK-SCN-F5** --- The Scanner should use non-invasive and non-aggressive options by default.
- **KRK-SCN-F6** --- The Scanner shall support both IPv4 and IPv6 scanning.
- **KRK-SCN-F7** --- The Scanner shall take the configuration from the YAML campaign file.
- **KRK-SCN-F8** --- The EtherCAT scanner shall enumerate slave devices on a specified network interface.
- **KRK-SCN-F9** --- The EtherCAT scanner shall read device identity (vendor ID, product code, revision, serial) from slave EEPROM.
- **KRK-SCN-F10** --- The EtherCAT scanner shall query port link status to determine network topology.
- **KRK-SCN-F11** --- The EtherCAT scanner shall perform vendor database lookup for human-readable device names.

#### 2.3.3 Non-Functional Requirements

- **KRK-SCN-N1** --- The Scanner should minimize network footprint during reconnaissance (e.g., default scan for a /24 subnet should generate < 1GB of traffic).
- **KRK-SCN-N2** --- The Scanner should ensure accuracy of service and protocol identification.
- **KRK-SCN-N4** --- The Scanner should complete discovery within a configurable timeout per target (e.g., default timeout of 5 minutes per host).

---

### 2.4 Reporter Component (KRK-REP)

#### 2.4.1 Architectural Requirements

- **KRK-REP-A1** --- The Reporter shall be responsible for results aggregation and reporting.
- **KRK-REP-A2** --- The Reporter shall consume outputs from the Runner and produce a report.

#### 2.4.2 Functional Requirements

- **KRK-REP-F1** --- The Reporter shall aggregate findings from all modules and scanners.
- **KRK-REP-F2** --- The Reporter should produce reports in the following formats:
    1.  **JSON** --- for machine readability. **Status: Implemented.**
    2.  **Attack Tree Markdown** --- per-target attack path evaluation with Mermaid diagrams. **Status: Implemented.**
    3.  _(Future)_ **Markdown** --- for human readability. **Status: Not implemented.**
    4.  _(Future)_ **Interactive HTML** --- for viewing in a browser. **Status: Not implemented.**
- **KRK-REP-F3** --- The Reporter shall include severity levels and result statuses.
- **KRK-REP-F4** --- The Reporter shall write all reports under the campaign's `result` directory.

#### 2.4.3 Non-Functional Requirements

- **KRK-REP-N1** --- The Reporter should generate reports with minimal delay after
  findings are available.
- **KRK-REP-N2** --- The Reporter should ensure report files are deterministic and reproducible.
- **KRK-REP-N3** --- The Reporter should maintain consistent schema across versions for backward compatibility.

---

### 2.5 Module Subsystem (KRK-MOD)

#### 2.5.1 Architectural Requirements

- **KRK-MOD-A1** --- The system shall define a clear, versioned interface (e.g., gRPC, ABI, CLI conventions) that all modules must adhere to.
- **KRK-MOD-A2** --- The system should provide a mechanism for discovering and registering available modules.

#### 2.5.2 Functional Requirements

- **KRK-MOD-F1** --- The system shall define a standardized data structure for passing results and findings from a module to the Runner.
- **KRK-MOD-F2** --- The Module interface shall support passing target information (e.g., host, port, classified tags) and campaign-specific configuration to the module.

---

### 2.6 Attack Tree Evaluator (KRK-ATE)

#### 2.6.1 Architectural Requirements

- **KRK-ATE-A1** --- The system shall include an Attack Tree evaluation component that processes findings from the Runner.

#### 2.6.2 Functional Requirements

- **KRK-ATE-F1** --- The evaluator shall load attack tree definitions from a specified YAML file.
- **KRK-ATE-F2** --- The evaluator shall process findings from the loaded attack trees to identify successful attack paths.
- **KRK-ATE-F3** --- The results of the attack tree evaluation shall be included in the final report.
- **KRK-ATE-F4** --- The system should be able to raise a distinct alert (e.g., log message, webhook) when a critical attack tree evaluates to true.
