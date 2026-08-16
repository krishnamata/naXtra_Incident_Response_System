# naXtra Incident Response System

## 1. Overview

**naXtra Incident Response System** is a modular, web-based security incident response platform designed to support the collection, analysis, detection, investigation, and response to security events across monitored systems.

The system combines endpoint log collection, rule-based detection, alert management, File Integrity Monitoring (FIM), threat intelligence integrations, evidence management, security playbooks, auditing, reporting, and AI-assisted security analysis within a centralized platform.

The system is implemented primarily using **Python and Flask** and uses a modular application architecture based on Flask Blueprints.

---

## 2. Key Capabilities

The current system includes the following major capabilities:

* Linux endpoint monitoring
* Windows endpoint monitoring
* Agent-based log collection
* Agentless security-event collection
* Centralized log processing
* Wazuh-compatible decoders
* Wazuh-compatible detection rules
* Rule-based alert generation
* Alert investigation and management
* File Integrity Monitoring (FIM)
* Evidence management
* Threat intelligence integrations
* Data Loss Prevention (DLP) functionality
* Security playbooks and response actions
* Role-based access control
* Multi-factor authentication (MFA)
* Security auditing
* Security reports
* AI-assisted security analysis
* Knowledge-base and retrieval-assisted analysis
* Dashboard and security-operations views

---

## 3. High-Level Architecture

```text
                    ┌──────────────────────────┐
                    │     Linux Endpoints      │
                    │      Linux Agents        │
                    └────────────┬─────────────┘
                                 │
                                 │ Security Events
                                 ▼
                    ┌──────────────────────────┐
                    │    Windows Endpoints     │
                    │     Windows Agents       │
                    └────────────┬─────────────┘
                                 │
                                 │ Security Events
                                 ▼
             ┌─────────────────────────────────────────┐
             │       naXtra Incident Response System   │
             │                                         │
             │              Flask Application          │
             ├─────────────────────────────────────────┤
             │                                         │
             │  Authentication & Authorization         │
             │  Dashboard                              │
             │  Log Processing                         │
             │  Decoders                               │
             │  Detection Engine                       │
             │  Alert Management                       │
             │  File Integrity Monitoring              │
             │  Threat Intelligence                    │
             │  Playbooks                              │
             │  Evidence Management                    │
             │  Audit & Reporting                      │
             │  AI-Assisted Analysis                   │
             │                                         │
             └───────────────────┬─────────────────────┘
                                 │
                 ┌───────────────┼────────────────┐
                 ▼               ▼                ▼
            Detection         Alerts          Investigation
                 │               │                │
                 └───────────────┼────────────────┘
                                 ▼
                         Incident Response
```

---

## 4. Application Architecture

The Flask application is organized into multiple functional modules.

The primary application factory is:

```text
app/__init__.py
```

The application is created through:

```python
create_app()
```

The main execution entry point is:

```text
app/run.py
```

The application initializes:

* Flask
* SQLAlchemy
* Flask-Migrate
* Flask-Mail
* Authentication
* Authorization
* Detection rules
* Wazuh decoders
* Multiple security-operation modules
* AI-related services
* Audit and reporting components

---

## 5. Main Application Modules

The following Flask Blueprints are currently registered by the application:

| Module        | Purpose                           |
| ------------- | --------------------------------- |
| `search`      | Security/event searching          |
| `auth`        | Authentication and MFA            |
| `api`         | API functionality                 |
| `dashboard`   | Main security dashboard           |
| `agents`      | Endpoint-agent management         |
| `alerts`      | Alert management                  |
| `dlp`         | Data Loss Prevention              |
| `playbook`    | Response playbooks                |
| `agent_logs`  | Agent log/API processing          |
| `detection`   | Detection and alert processing    |
| `fim`         | File Integrity Monitoring         |
| `ai_insights` | AI-assisted security insights     |
| `mistral`     | Mistral-related API functionality |
| `naxtraai`    | naXtra AI functionality           |
| `sec_ops`     | Security operations functionality |
| `stats`       | Security statistics               |
| `audit`       | Audit and reporting functionality |

---

## 6. Detection Architecture

The system uses a rule-based detection engine built around Wazuh-compatible rules.

At application startup, the system loads detection rules from:

```text
app/rules/wazuh-ruleset/rules
```

The rule loader is implemented in:

```text
app/rules/rules_loader.py
```

The detection engine is implemented in:

```text
app/rules/rules_engine.py
```

The application therefore follows this general processing model:

```text
Security Event
      │
      ▼
Log Collection
      │
      ▼
Decoder
      │
      ▼
Normalized Event
      │
      ▼
Detection Rules
      │
      ▼
Rule Engine
      │
      ▼
Alert
      │
      ▼
Investigation / Response
```

---

## 7. Endpoint Monitoring

### Linux

The Linux endpoint components are located under:

```text
app/agents/linux_agents/
```

The Linux agent includes:

* Agent implementation
* Configuration
* Installation script
* Journal/log processing support

### Windows

The Windows endpoint agent is located under:

```text
app/agents/windows_agent/
```

It includes:

* Windows agent implementation
* Configuration
* PowerShell installation script

---

## 8. File Integrity Monitoring

File Integrity Monitoring functionality is located under:

```text
app/fim/
```

The system supports establishing file baselines and detecting changes to monitored files.

FIM functionality includes cryptographic hashing and baseline management.

---

## 9. AI-Assisted Analysis

AI-related components are distributed across:

```text
app/naxtraai/
app/ai_assistant.py
app/generator.py
app/mistral_api.py
app/routes/naxtraai_routes.py
```

The AI subsystem is intended to assist security analysts with the interpretation and analysis of security information.

AI functionality is an **assistance layer** and does not replace the underlying detection and incident-response mechanisms.

---

## 10. Authentication and Security

The application provides authentication functionality through:

```text
app/auth/
```

The current application includes:

* User authentication
* Password hashing
* Role-based permissions
* Multi-factor authentication
* Session-based user context

Role permissions are loaded from:

```text
app/config/role_permissions.yaml
```

---

## 11. Database

The application uses SQLAlchemy for database interaction.

Database initialization is performed through:

```python
db.init_app(app)
```

Database migrations are supported through:

```python
migrate.init_app(app, db)
```

The database models are primarily defined in:

```text
app/models.py
```

---

## 12. Starting the Application

From the project root:

```bash
cd /var/www/modular-soar
```

Start the application with:

```bash
PYTHONPATH=. app/venv/bin/python app/run.py
```

The current Flask configuration starts the application on:

```text
0.0.0.0:5001
```

Therefore, from the same machine, the web application is available at:

```text
http://127.0.0.1:5001
```

The root URL redirects to:

```text
/dashboard/
```

---

## 13. Development Mode

The current `app/run.py` configuration starts Flask with:

```python
debug=True
```

and:

```python
use_reloader=False
```

This configuration is suitable for development and testing.

**It should not be assumed to be production-ready.**

Before deploying the system in a production environment, the Flask development server and debug mode should be replaced with an appropriate production deployment architecture.

---

## 14. Detection Rules at Startup

During startup, `app/run.py` loads the detection rules:

```python
rules = load_rules('app/rules/wazuh-ruleset/rules')
app.rule_engine = RuleEngine(rules)
```

This means the detection engine is initialized when the application starts.

If the detection-rule directory is unavailable or contains invalid rules, application startup or detection functionality may be affected.

---

## 15. Current Project Status

The repository contains the implementation of the naXtra Incident Response System together with its supporting components, detection rules, agents, integrations, AI components, and operational modules.

The documentation is being developed alongside the existing implementation so that users can understand:

1. How to install the system
2. How to configure it
3. How to start it
4. How to deploy endpoint agents
5. How logs are collected
6. How detection works
7. How alerts are investigated
8. How incidents are handled
9. How AI-assisted analysis works
10. How administrators manage the platform

---

## 16. Documentation Roadmap

Detailed documentation will be maintained separately for:

* Installation
* Configuration
* Architecture
* Linux Agent
* Windows Agent
* Log Collection
* Detection Rules
* Alert Management
* Incident Investigation
* File Integrity Monitoring
* Threat Intelligence
* AI-Assisted Analysis
* Playbooks
* Evidence Management
* Authentication and MFA
* Auditing
* Reporting
* Troubleshooting
* Security Hardening
* Development and Extension

---

## 17. Project Name

The official project name used in the documentation is:

**naXtra Incident Response System**

The term **SOAR** is intentionally not used as the product name because SOAR has a specific meaning in cybersecurity: **Security Orchestration, Automation and Response**.

The existing source-code identifiers and repository names may still contain `naXtraSOAR` and will be addressed separately where necessary.
