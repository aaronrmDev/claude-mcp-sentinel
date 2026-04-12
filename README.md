# MCP Sentinel

Security agent for Claude Code and Cowork. Scans your installed Skills and MCP servers against live vulnerability databases, verifies source integrity, and detects malicious code through coherence analysis.

**Author:** Rafael Tunón Sánchez ([@soy-rafa](https://github.com/soy-rafa))
**License:** [MIT](./LICENSE)
**Created:** April 2026

## Why

The AI skills ecosystem is growing fast — but so are the attacks. [Snyk's ToxicSkills study](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) found that **36% of skills contain security flaws**, including 76 with confirmed malicious payloads. MCP Sentinel protects you so you can keep installing and experimenting without worrying about what might slip through.

## What it does

**1. Threat intelligence scanning**
Checks every installed skill and MCP server against 6 live databases maintained by the community: GitHub Advisory DB, vulnerablemcp.info, mcpscan.ai, Snyk, ClawHub/VirusTotal, and Reddit r/ClaudeAI.

**2. Source integrity verification**
When you're about to install a skill, Sentinel finds the official original source and compares it against your copy. If someone took a trusted skill, injected malicious code, and redistributed it — Sentinel catches the difference.

**3. Coherence analysis**
Analyzes whether everything a skill does matches its stated purpose. A token optimizer that tries to access your SSH keys? A markdown formatter that sends your credentials to an external server? Sentinel flags the mismatch and shows you exactly which actions belong and which don't.

**4. Update diff detection**
Stores a snapshot of every installed skill. If an update changes something, Sentinel diffs it and runs coherence analysis on the new code. This catches supply chain attacks — when a trusted skill pushes a poisoned update.

**5. Scheduled monitoring**
Runs automatically every morning to re-scan everything. A skill that was safe yesterday might have a new CVE reported today.

## Install

Download `mcp-sentinel.skill` from [Releases](../../releases) and double-click to install.

Or manually: copy the `SKILL.md` and `references/` folder into `.claude/skills/mcp-sentinel/` in your project (or `~/.claude/skills/mcp-sentinel/` for global).

## Usage

Just talk to Claude:

- *"Scan my project for security issues"*
- *"Is this MCP server safe to install?"*
- *"Check if this skill has been tampered with"*
- *"Run a security audit"*

MCP Sentinel triggers automatically when it detects you're about to install something or when you mention security concerns.

## How it works

MCP Sentinel is a Claude skill — a `.md` file with structured instructions that tells Claude how to act as a security agent. It uses Claude's built-in tools (WebSearch, Read, Write, Bash, Glob, Grep) to scan files, search databases, and generate reports. No external dependencies, no API keys, no infrastructure.

All analysis happens locally + public web searches. Your code and credentials never leave your machine.

## Threat database

Sentinel maintains a local JSON database at `.security/mcp-sentinel-threats.json` that grows with each scan. It stores:

- Inventory of installed skills/MCPs with content snapshots
- Known threats with CVE IDs and severity scores
- Community alerts from Reddit and Discord
- Change history for update diff detection
- Structured threat reports compatible with future community sharing

## Benchmarks

Tested across 5 scenarios (full audit, pre-install check, suspicious skill investigation, source integrity verification, coherence analysis):

| | With MCP Sentinel | Without (baseline) |
|---|---|---|
| Detection rate | **100%** | 43–67% |
| Source verification | Yes | No |
| Coherence map | Yes | No |
| Threat database | Yes | No |

## Contributing

Found a bug? Have an idea? Open an issue or PR. This is a community project.

## Legal

### License

This project is licensed under the [MIT License](./LICENSE). Copyright (c) 2026 Rafael Tunón Sánchez.

You are free to use, copy, modify, merge, publish, distribute, sublicense, and sell copies of this software, provided that the original copyright notice and this permission notice are included in all copies or substantial portions of the software.

### Attribution

If you redistribute this project, in whole or in part, or create derivative works based on it, you must give appropriate credit to the original author. This includes:

- Keeping the copyright notice in the LICENSE file intact
- Mentioning the original project and author in any derivative work's documentation

### Original work

MCP Sentinel was conceived, designed, and developed by **Rafael Tunón Sánchez** in April 2026. The concept, architecture, skill instructions, coherence analysis methodology, update diff detection system, and threat database schema are original work by the author.

The full commit history of this repository serves as a public, timestamped record of authorship.

### Disclaimer

This software is provided "as is", without warranty of any kind. MCP Sentinel is a security tool that helps detect potential threats, but it does not guarantee the detection of all vulnerabilities or malicious code. Users are responsible for their own security decisions. The author is not liable for any damages arising from the use of this software.

### Trademarks

"MCP Sentinel" is the project name chosen by the author. GitHub, Claude, Anthropic, Snyk, and other product names mentioned in this repository are trademarks of their respective owners.

---

Built with care by [@soy-rafa](https://github.com/soy-rafa)
