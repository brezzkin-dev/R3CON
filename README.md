R3CON

<p align="center">
  <img src="https://i.imgur.com/LVrtJuf.png" alt="R3CON Banner" width="100%">
</p><p align="center">
  <strong>Multi-Module Cybersecurity Toolkit</strong>
  <br>
  Security research, diagnostics, and controlled testing.
</p><p align="center">
  <img src="https://img.shields.io/badge/Project-R3CON-red?style=flat-square" alt="Project">
  <img src="https://img.shields.io/badge/Platform-Android%20%7C%20Linux%20%7C%20PC-lightgrey?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/Language-Python-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/Status-Development-orange?style=flat-square" alt="Status">
</p>---

Overview

R3CON is a multi-module cybersecurity toolkit that brings several security-related utilities into one command-line interface.

The project combines network testing, system-level utilities, Minecraft-related testing modules, information gathering, and other experimental security components.

R3CON is intended for security research, development, and controlled environments. Some included modules can perform sensitive operations and may affect systems, networks, accounts, or third-party services if misused.

This is not a general-purpose harmless utility collection.

Modules

Module| Description
"CINT"| Integrated utility and security-related components.
"FLOOD"| Network traffic and connection testing utilities.
"MC-KILLER"| Minecraft-related testing and diagnostic components.
"SCAMBLR"| Communication, phone-number, and information-gathering utilities.
"fsociety"| Additional security and utility modules.

Module availability and functionality depend on their individual implementations and dependencies.

Main Features

- Multi-platform interface — Android and PC environment selection.
- Dynamic module loading — access registered modules through the main interface.
- Root detection — identifies Android root availability.
- Root-dependent options — certain features are restricted to rooted environments.
- Module selection — launch available components from the main menu.
- Self-test — built-in diagnostic option for checking application behavior.
- Dependency management — Python requirements are listed in "requirements.txt".

Environment

Environment| Support
Android / Termux| Supported environment
Linux| Supported environment
Windows| PC environment; compatibility may vary
macOS| PC environment; compatibility may vary

Some modules may require additional system packages, permissions, binaries, or elevated privileges.

Requirements

- Python 3
- pip
- Git
- Required packages listed in "requirements.txt"

Some modules have additional requirements. Check their respective directories before running them.

Installation

Clone the repository:

git clone https://github.com/brezzkin-dev/R3CON.git

Enter the project directory:

cd R3CON

Install Python dependencies:

pip install -r requirements.txt

Run R3CON:

python r3con.py

On Termux, use "python" or "python3" depending on your installation.

Interface

The main interface provides module selection and environment-specific options.

Input| Action
"99"| Run the built-in self-test
"0"| Exit
"q"| Exit
"exit"| Exit

Other options are presented by the application menu and depend on the available modules.

Security Notice

R3CON contains components that may have security-sensitive capabilities.

Depending on the module and its implementation, operations may involve:

- Network traffic generation and connection testing.
- Packet capture or network inspection.
- Minecraft server and protocol testing.
- OSINT and phone-number information gathering.
- Communication service integrations.
- Privileged or system-level operations.

These capabilities can create real operational and privacy risks. A module's presence in this repository does not mean every operation is safe, reliable, or suitable for production systems.

Responsible Use

Use R3CON only:

- On systems you own.
- In environments where you have explicit authorization.
- In isolated labs and controlled test networks.
- For legitimate research, diagnostics, and educational purposes.

Do not use this project to disrupt third-party services, access accounts without permission, capture private traffic without authorization, send unsolicited communications, or collect information unlawfully.

The author is not responsible for misuse, damage, service interruptions, or unauthorized activity.

Development Status

R3CON is an ongoing project. Features, modules, dependencies, and platform compatibility may change.

Not every module has been independently audited or verified for production use. Review the source code and understand the behavior of each component before execution.

Issues and contributions should include clear reproduction steps and relevant environment details.

Author

L1ghtXr

Repository: "brezzkin-dev/R3CON" (https://github.com/brezzkin-dev/R3CON)

License

License has not been specified yet.

No open-source license is currently declared for this project. Until a license is added, do not assume that redistribution, modification, or commercial use is permitted.
