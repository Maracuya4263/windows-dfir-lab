<div align="center">

# Windows DFIR & Live Forensics Lab

**Live evidence acquisition and digital-forensics coursework on Windows incidents**

Miguel Ángel Rodríguez Bohórquez · Bogotá, Colombia
[mrodriguezbohorquez23@gmail.com](mailto:mrodriguezbohorquez23@gmail.com)

</div>

---

This repository collects hands-on **digital forensics and incident response (DFIR)** work produced during
cybersecurity coursework at the **Universidad Nacional de Colombia**, under **Prof. José Javier Moreno
Corredor** (*Operaciones en Ciberseguridad II* / *Ciberseguridad II*). It contains a set of **live
evidence-acquisition scripts** and two **forensic case reports**, all built and run in an **isolated lab**.
The focus is defensive: acquiring evidence soundly, then reconstructing what happened on a compromised
Windows host.

> **Language note:** the reports and the acquisition guide are written in **Spanish**; this README is in
> English. **Scope:** all work was performed in a controlled, isolated lab for educational and defensive
> purposes. No malware binaries are distributed.

## Live evidence-acquisition toolkit

Five PowerShell scripts that acquire volatile and non-volatile evidence from a live Windows host, in
**order of volatility** (RFC 3227), streaming everything over an **encrypted (TLS 1.2)** channel to the
analyst workstation. Shared design principles: minimal footprint on the victim (fileless where possible),
**in-flight SHA-256 integrity**, and chain-of-custody metadata.

| Order | Script | Captures | Victim disk impact |
|---|---|---|---|
| 0 | `scripts/Script0_RAM.ps1` | Full physical memory (winpmem → TLS) | None (diskless / read-only) |
| 1 | `scripts/ScriptA_Red_Config.ps1` | Processes, TCP connections, routes, interfaces, ARP | None (RAM → TLS) |
| 2 | `scripts/ScriptB_Pktmon_Red.ps1` | Network traffic capture (pktmon → pcapng) | Minimal (single flush) |
| 3 | `scripts/ScriptC_Registro.ps1` | Registry hives (SAM, SYSTEM, SOFTWARE) + custody manifest | Temporary (always cleaned) |
| 4 | `scripts/ScriptD_Disco.ps1` | Raw disk image (dd.exe → TLS) | None (diskless) |

Highlights: order-of-volatility sequencing; in-flight hashing so the source hash can be compared against
the received file; per-hive hashing and a chain-of-custody manifest for the registry; `try/finally`
cleanup so hives containing NTLM hashes never linger on disk; and pre-flight validation for `dd` output.
Full documentation (Spanish), with each script explained and embedded, is in
**[`docs/adquisicion_evidencia.md`](docs/adquisicion_evidencia.md)**.

## Forensic case reports

Located in [`informes/`](informes/) (Spanish, `.pdf`):

- **`informe_forense_sysinternals.pdf` — Windows forensics of an in-memory implant.**
  Forensic analysis of a Windows 10 VM compromised by a **Sliver** implant delivered through a loader
  whose behaviour is consistent with indirect syscalls and reflective in-memory execution. Using the
  **Sysinternals** suite and **Sysmon**, the report correlates seven behavioural findings (Process
  Explorer, TCPView, Sigcheck, ListDLLs, VMMap, Autoruns) into an incident timeline and IoCs, maps them to
  **MITRE ATT&CK**, and derives a layered detection strategy — demonstrating that a stealthy, fileless
  implant still leaves residual, correlatable evidence. *(Course: Ciberseguridad II.)*

- **`informe_forense_caja_negra.pdf` — Windows Registry & Event Log forensics ("black-box" case).**
  An end-to-end DFIR case built from a disk/registry image: chain of custody and artifact inventory,
  system profiling, **eight technical findings** graded by evidentiary strength (unofficial activation
  tooling, weak security posture, removable-media usage, remote-access tools, user activity, recurrent
  unexpected shutdowns, `$I30`/NTFS artifacts, PowerShell activity), a consolidated timeline of the
  critical window, structured hypothesis evaluation, stated limitations, and prioritised recommendations.

## Repository layout

```
.
├── README.md                       (this file, English)
├── scripts/                        acquisition scripts (PowerShell)
│   ├── Script0_RAM.ps1
│   ├── ScriptA_Red_Config.ps1
│   ├── ScriptB_Pktmon_Red.ps1
│   ├── ScriptC_Registro.ps1
│   └── ScriptD_Disco.ps1
├── docs/
│   └── adquisicion_evidencia.md    acquisition guide (Spanish, scripts documented + embedded)
└── informes/                       forensic case reports (Spanish, .pdf)
    ├── informe_forense_sysinternals.pdf
    └── informe_forense_caja_negra.pdf
```

## Skills demonstrated

Live evidence acquisition in order of volatility (RAM, network, packet capture, registry, disk);
memory acquisition with winpmem; network and packet forensics (pktmon, Wireshark); Windows Registry and
Event Log analysis; NTFS artifacts (`$I30`); Sysinternals and Sysmon behavioural analysis; chain of
custody and evidence integrity (SHA-256, manifests); MITRE ATT&CK mapping; detection engineering; and
secure PowerShell tooling (TLS streaming, fileless design, robust error handling and cleanup).

---

*Educational DFIR coursework performed in an isolated lab, for defensive and detection purposes only.*
© 2026 Miguel Ángel Rodríguez Bohórquez.
