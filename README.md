# OpenCTI EUVD Connector

This connector imports vulnerability data from the **European Union Vulnerability Database (EUVD)** into OpenCTI. The EUVD is maintained by ENISA (European Union Agency for Cybersecurity) and provides aggregated, reliable, and actionable vulnerability information affecting ICT products and services.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#requirements)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Configuration File](#configuration-file)
- [Installation](#installation)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Data Mapping](#data-mapping)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## Introduction

The **European Union Vulnerability Database (EUVD)** was established under the NIS2 Directive and is part of the EU Cyber Resilience Act (CRA). It serves as Europe's counterpart to the US National Vulnerability Database (NVD), enriching CVE records with additional metadata such as CVSS scores, EPSS scores, and exploitation status.

This connector:
- Fetches vulnerability data from the EUVD API
- Converts vulnerabilities to STIX 2.1 Vulnerability objects
- Imports them into OpenCTI
- Supports incremental updates and historical imports

## Features

- **Full EUVD Integration**: Access all vulnerabilities from the European Vulnerability Database
- **Incremental Updates**: Only fetch new or modified vulnerabilities since last run
- **Historical Import**: Option to import historical data from a specific year
- **Filtering Options**:
  - Filter by minimum CVSS score
  - Import only exploited vulnerabilities
  - Import only critical vulnerabilities (CVSS ≥ 9.0)
- **Rich Metadata**:
  - CVSS scores and vectors
  - EPSS (Exploit Prediction Scoring System) scores
  - CVE cross-references
  - Affected vendors and products
  - External references and advisories
- **STIX 2.1 Compliance**: Proper conversion to STIX Vulnerability objects

## Requirements

- **OpenCTI Platform >= 6.9.10** (pycti version must match OpenCTI version)
- Python >= 3.10 (for manual deployment)
- Docker and Docker Compose (for containerized deployment)
- Network access to `euvdservices.enisa.europa.eu`

> **Important**: The `pycti` version in `requirements.txt` must match your OpenCTI platform version. If you use a different OpenCTI version, update `pycti==6.9.10` accordingly.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENCTI_URL` | Yes | - | URL of the OpenCTI platform |
| `OPENCTI_TOKEN` | Yes | - | API token for OpenCTI |
| `CONNECTOR_ID` | Yes | - | Unique UUIDv4 for this connector instance |
| `CONNECTOR_TYPE` | Yes | `EXTERNAL_IMPORT` | Connector type |
| `CONNECTOR_NAME` | No | `EUVD` | Display name in OpenCTI |
| `CONNECTOR_SCOPE` | No | `vulnerability` | Data scope |
| `CONNECTOR_LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `CONNECTOR_DURATION_PERIOD` | No | `PT6H` | Run interval in ISO 8601 format |
| `CONNECTOR_RUN_AND_TERMINATE` | No | `false` | Exit after single run |
| `EUVD_BASE_URL` | No | `https://euvdservices.enisa.europa.eu/api` | EUVD API base URL |
| `EUVD_INTERVAL` | No | `6` | Interval between runs in hours |
| `EUVD_MAX_DATE_RANGE` | No | `30` | Maximum date range for initial fetch (days) |
| `EUVD_MAINTAIN_DATA` | No | `true` | Fetch only changes since last run |
| `EUVD_PULL_HISTORY` | No | `false` | Enable historical import |
| `EUVD_HISTORY_START_YEAR` | No | `2024` | Start year for historical import |
| `EUVD_MIN_SCORE` | No | `0` | Minimum CVSS score to import (0-10) |
| `EUVD_IMPORT_EXPLOITED_ONLY` | No | `false` | Import only exploited vulnerabilities |
| `EUVD_IMPORT_CRITICAL_ONLY` | No | `false` | Import only critical vulnerabilities |

### Configuration File

Create `config.yml` based on `config.yml.sample`:

```yaml
opencti:
  url: 'http://localhost:8080'
  token: 'your-api-token'

connector:
  id: 'your-uuid-v4'
  type: 'EXTERNAL_IMPORT'
  name: 'EUVD'
  scope: 'vulnerability'
  log_level: 'info'
  duration: 'PT6H'

euvd:
  base_url: 'https://euvdservices.enisa.europa.eu/api'
  interval: 6
  max_date_range: 30
  maintain_data: true
  pull_history: false
  history_start_year: 2024
  min_score: 0
  import_exploited_only: false
  import_critical_only: false
```

## Installation

### Docker Deployment

1. **Clone or download the connector:**

```bash
git clone <repository-url>
cd euvd-connector
```

2. **Configure environment variables:**

Edit `docker-compose.yml` and replace the `ChangeMe` values:

```yaml
environment:
  - OPENCTI_URL=http://your-opencti-instance:8080
  - OPENCTI_TOKEN=your-api-token
  - CONNECTOR_ID=a-valid-uuid-v4
```

3. **Build and start the connector:**

```bash
docker-compose up -d
```

4. **View logs:**

```bash
docker-compose logs -f connector-euvd
```

### Manual Deployment

1. **Create a virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate
```

2. **Install dependencies:**

```bash
cd src
pip install -r requirements.txt
```

3. **Configure the connector:**

```bash
cp config.yml.sample config.yml
# Edit config.yml with your settings
```

4. **Run the connector:**

```bash
python main.py
```

## Usage

### Initial Run

For the first run, the connector will import vulnerabilities from the last `max_date_range` days (default: 30 days).

### Historical Import

To import historical data, set:

```yaml
euvd:
  pull_history: true
  history_start_year: 2020  # Adjust as needed
```

**Note:** Historical imports can take a long time due to API rate limits (1 request per 6 seconds).

### Incremental Updates

With `maintain_data: true` (default), the connector only fetches vulnerabilities modified since the last run, reducing API calls and processing time.

### Import Modes

1. **All vulnerabilities** (default): Import all vulnerabilities above `min_score`
2. **Exploited only**: Set `import_exploited_only: true` to import only known exploited vulnerabilities
3. **Critical only**: Set `import_critical_only: true` to import only vulnerabilities with CVSS ≥ 9.0

### Forcing a Manual Run

In OpenCTI:
1. Navigate to **Data → Connectors**
2. Find the EUVD connector
3. Click the refresh button to trigger an immediate run

## Data Mapping

### EUVD to STIX Mapping

| EUVD Field | STIX Field | Notes |
|------------|------------|-------|
| `id` | `external_references` | EUVD ID (e.g., EUVD-2025-12345) |
| `aliases` (CVE) | `name` | CVE ID preferred if available |
| `description` | `description` | Enhanced with vendor/product info |
| `datePublished` | `created` | Publication date |
| `dateUpdated` | `modified` | Last modification date |
| `baseScore` | `x_opencti_base_score` | CVSS score |
| `baseScoreVector` | `x_opencti_attack_vector` | CVSS vector string |
| `epss` | `x_opencti_epss_score` | EPSS probability score |
| `references` | `external_references` | Additional reference URLs |

### Labels

The connector applies the following labels:
- `euvd`: Applied to all imported vulnerabilities
- `critical`: Applied when CVSS ≥ 9.0
- `exploited`: Applied when marked as exploited in EUVD

### External References

Each vulnerability includes references to:
- EUVD record URL
- CVE record (when available)
- Additional vendor advisories and references

## Troubleshooting

### Common Issues

**Connection refused to EUVD API:**
- Verify network connectivity to `euvdservices.enisa.europa.eu`
- Check if your firewall allows outbound HTTPS connections

**Rate limiting errors:**
- The connector respects EUVD's rate limit (1 request per 6 seconds)
- Reduce concurrent connector instances if running multiple

**No vulnerabilities imported:**
- Check if `min_score` is set too high
- Verify date range includes recent vulnerabilities
- Check OpenCTI logs for parsing errors

**Empty vulnerability descriptions:**
- Some EUVD records have minimal descriptions
- The connector enhances descriptions with available vendor/product info

### Logs

Enable debug logging for detailed information:

```yaml
connector:
  log_level: 'debug'
```

Or via environment variable:

```bash
export CONNECTOR_LOG_LEVEL=debug
```

### API Response Example

The EUVD API returns data in this format:

```json
{
  "items": [
    {
      "id": "EUVD-2025-12345",
      "description": "A vulnerability in...",
      "datePublished": "Jan 15, 2025, 10:30:00 AM",
      "dateUpdated": "Jan 16, 2025, 2:15:00 PM",
      "baseScore": 7.5,
      "baseScoreVersion": "3.1",
      "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "aliases": "CVE-2025-12345\n",
      "epss": 0.0234,
      "enisaIdVendor": [...],
      "enisaIdProduct": [...]
    }
  ],
  "total": 1234
}
```

## References

- [EUVD Official Website](https://euvd.enisa.europa.eu/)
- [EUVD API Documentation](https://euvd.enisa.europa.eu/apidoc)
- [ENISA Official Website](https://www.enisa.europa.eu/)
- [OpenCTI Documentation](https://docs.opencti.io/)
- [OpenCTI Connectors Repository](https://github.com/OpenCTI-Platform/connectors)
- [NIS2 Directive](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive)
- [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)

## License

Apache License 2.0

## Author

OpenCTI Community Connector

---

**Disclaimer:** This connector is not officially maintained by ENISA. The EUVD API is in beta and may change. Use in production environments at your own risk.
