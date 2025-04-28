# Elasticsearch Windows Event Analysis MCP Tools

This project provides a set of tools for analyzing Windows event logs stored in Elasticsearch. The tools are designed to help security analysts investigate potential security incidents and identify malicious activity.

## Available Tools

| Tool | Description |
|------|-------------|
| `list_hosts` | Lists all unique hosts (computer_name) from winlogbeat indices. |
| `get_events` | Retrieves events with filtering capabilities for host name, provider name, event ID, and time range. |
| `prepare_llm_analysis` | Formats events for analysis by LLM with customizable focus areas. Deduplicates events based on specific fields for Sysmon event IDs. |
| `get_event_ids` | Gets all event IDs, optionally filtered by provider name and time range. |
| `get_providers` | Retrieves all event provider names available in the logs. |
| `health_check` | Checks the health of the MCP server, Elasticsearch connection, and Threat Intelligence API. |
| `search_events` | Searches events by keyword in winlog.event_data and message fields with optional host name and time range filtering. |
| `enrich_events_with_ti` | Enriches events with threat intelligence data from external sources. |
| `lookup_ioc` | Looks up a specific indicator of compromise (IOC) in threat intelligence sources. |
| `search_events_by_ioc` | Searches for events related to a specific indicator of compromise (IOC). |
| `hunt_for_ioc_patterns` | Hunts for patterns of IOCs across events to identify potential attack campaigns. |
| `generate_threat_analysis` | Generates a RAG-based threat analysis for the given events. |
| `extract_iocs_from_events` | Extracts potential indicators of compromise (IOCs) from the given events. |

## Features

- Field-based deduplication for Sysmon events
- Integration with external threat intelligence sources
- Support for various types of IOCs (IP addresses, domains, file hashes)
- Customizable focus areas for event analysis
- Health monitoring of services

## Install

1. Setup virtual environment
```
uv venv
source venv/bin/activate (bash)
.\venv\Scripts\activate (Windows)
uv pip install elasticsearch==8.12.1 fastmcp requests typing_extensions
```
2.  Set environment variables (optional)

## Claude Desktop Config
claude_desktop_config.json
```
{
  "mcpServers": {
      "elasticsearch": {
          "command": "<full path to uv>",
          "args": [
              "--directory",
              "<mcp server directory path>",
              "run",
              "mcp_hunt_server_ti.py"
          ]
      }
  }
}
```


## MCP Threat Intelligence Service

This service provides threat intelligence capabilities for the MCP Windows Event Analysis toolkit.

### API Endpoints

- `/health` - Check the health of the service
- `/enrich_events` - Enrich events with threat intelligence
- `/lookup_ioc` - Look up a specific IOC against threat intelligence sources
- `/search_related_events` - Search for events related to a specific indicator
- `/hunt_for_ioc_patterns` - Hunt for patterns of IOCs across events
- `/generate_rag_summary` - Generate a RAG-based summary of events with threat intelligence context

### Setup

1. Fill in your API keys in the `.env` file
2. Ensure Elasticsearch is accessible with the provided configuration
3. Start the service using the systemd service file or manually

### Running the Service

### Using systemd (recommended)

```bash
sudo cp threat-intel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable threat-intel
sudo systemctl start threat-intel
```

### Manual Start

```bash
source venv/bin/activate
python -m uvicorn server:app --host 0.0.0.0 --port 8000
```

### Integrating with MCP

Update your MCP configuration to point to this service:

```
THREAT_INTEL_HOST=localhost
THREAT_INTEL_PORT=8000
```

## The ELK Stack

1. Copy logstash.conf to ./logstash/pipeline/
2. Copy docker-compose.yml to current directory
3. Then run the following command:
```
docker compose up -d
```
