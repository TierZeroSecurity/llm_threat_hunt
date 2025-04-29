import os
import json
from typing import List, Optional, Dict, Any
from fastmcp import FastMCP
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, AuthenticationException
import logging
import requests
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='mcp_server.log'
)
logger = logging.getLogger("mcp-server")

# Threat Intelligence API configuration
THREAT_INTEL_HOST = os.getenv("THREAT_INTEL_HOST", "localhost")
THREAT_INTEL_PORT = int(os.getenv("THREAT_INTEL_PORT", "8000"))
THREAT_INTEL_URL = f"http://{THREAT_INTEL_HOST}:{THREAT_INTEL_PORT}"

# Elasticsearch configuration
ES_SCHEME = os.getenv("ES_SCHEME", "http")
default_port = "9200" if ES_SCHEME == "http" else "9243"
ES_PORT = int(os.getenv("ES_PORT", default_port))
ES_HOST = os.getenv("ES_HOST", "<your es IP>")
ES_USER = os.getenv("ES_USER", "")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")
ES_API_KEY = os.getenv("ES_API_KEY", "")

# Initialize Elasticsearch client
try:
    hosts = [{"host": ES_HOST, "port": ES_PORT, "scheme": ES_SCHEME}]
    if ES_API_KEY:
        es = Elasticsearch(
            hosts,
            api_key=ES_API_KEY,
        )
    elif ES_USER and ES_PASSWORD:
        es = Elasticsearch(
            hosts,
            basic_auth=(ES_USER, ES_PASSWORD),
        )
    else:
        es = Elasticsearch(hosts)
except Exception as e:
    logger.error(f"Failed to initialize Elasticsearch client: {str(e)}")
    raise

# Initialize MCP server
mcp_server = FastMCP("Elasticsearch Windows Event Analysis MCP", dependencies=["elasticsearch", "requests"])

# Define key fields for field-based deduplication
specific_key_fields = {
    1: ['CommandLine', 'ParentImage', 'ParentCommandLine'],  # Process Creation
    3: ['SourceIp', 'SourcePort', 'DestinationIp', 'DestinationPort', 'Protocol'],  # Network Connection
    5: ['Image'],  # Process Termination
    7: ['ImageLoaded', 'Image'],  # Image Load
    8: ['SourceProcessId', 'TargetProcessId'],  # CreateRemoteThread (Memory Injection)
    10: ['SourceProcessId', 'TargetProcessId'],  # Process Access (cred theft etc.)
    11: ['TargetFilename', 'Image'],  # File Create
    12: ['EventType', 'TargetObject'],  # Registry CreateKey
    13: ['EventType', 'TargetObject'],  # Registry Value Set
    14: ['TargetObject'],  # Registry Value Deleted
    22: ['QueryName', 'Image'],  # DNS Query
    23: ['Image', 'TargetFilename'],  # File Delete (legacy, optional)
    25: ['SourceProcessId', 'TargetProcessId', 'TamperOperation'],  # Process Tampering (e.g., hollowing)
    26: ['TargetFilename', 'Image'],  # File Delete Detected (better version)
}

# Function to generate a deduplication key for an event
def get_event_key(event):
    winlog = event.get("winlog", {})
    computer_name = winlog.get("computer_name", "None")
    event_id = winlog.get("event_id", "None")
    event_data = winlog.get("event_data", {})
    
    if event_id in specific_key_fields and isinstance(event_id, int):
        fields = specific_key_fields[event_id]
        key_parts = [computer_name, str(event_id)] + [str(event_data.get(field, "None")) for field in fields]
        return tuple(key_parts)
    return None

# Function to remove duplicates based on field-based deduplication
def remove_duplicates(events):
    seen = set()
    unique_events = []
    for event in events:
        key = get_event_key(event)
        if key and key not in seen:
            seen.add(key)
            unique_events.append(event)
        elif not key:
            unique_events.append(event)
    return unique_events

# Tool 1: List all hosts
@mcp_server.tool()
async def list_hosts() -> dict:
    """List all unique hosts (computer_name) from winlogbeat indices."""
    try:
        query = {
            "size": 0,
            "aggs": {
                "unique_hosts": {
                    "terms": {
                        "field": "winlog.computer_name.keyword",
                        "size": 10000
                    }
                }
            }
        }

        response = es.search(index="winlogbeat-*", body=query)
        hosts = [bucket["key"] for bucket in response["aggregations"]["unique_hosts"]["buckets"]]

        return {"hosts": hosts, "count": len(hosts)}

    except ConnectionError:
        logger.error("Elasticsearch connection error")
        return {"error": "Cannot connect to Elasticsearch"}
    except AuthenticationException:
        logger.error("Elasticsearch authentication failed")
        return {"error": "Elasticsearch authentication failed"}
    except Exception as e:
        logger.error(f"Error retrieving hosts: {str(e)}")
        return {"error": f"Error retrieving hosts: {str(e)}"}

# Tool 2: Get events with filters
@mcp_server.tool()
async def get_events(host_name: Optional[str] = None, provider_name: Optional[str] = None, event_id: Optional[str] = None,
                     start_time: Optional[str] = None, end_time: Optional[str] = None, size: int = 50) -> dict:
    """Get events with filtering capabilities for host name, provider name, event ID, and time range.
    Defaults to events from the last 2 days if no time range is specified."""
    try:
        es_query = {"bool": {"filter": []}}

        # Add existing filters
        if host_name:
            es_query["bool"]["filter"].append({"term": {"winlog.computer_name.keyword": host_name}})
        if provider_name:
            es_query["bool"]["filter"].append({"term": {"winlog.provider_name.keyword": provider_name}})
        if event_id:
            es_query["bool"]["filter"].append({"term": {"winlog.event_id": event_id}})

        # Add time range filter (default to last 2 days if not specified)
        time_range = {"range": {"@timestamp": {}}}
        if start_time:
            time_range["range"]["@timestamp"]["gte"] = start_time
        else:
            time_range["range"]["@timestamp"]["gte"] = "now-7d"
        if end_time:
            time_range["range"]["@timestamp"]["lte"] = end_time
        else:
            time_range["range"]["@timestamp"]["lte"] = "now"
        es_query["bool"]["filter"].append(time_range)

        # Use match_all if no filters are specified
        if not es_query["bool"]["filter"]:
            es_query = {"match_all": {}}

        response = es.search(
            index="winlogbeat-*",
            body={
                "query": es_query,
                "size": size,
                "_source": ["winlog", "@timestamp"],
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )

        events = [
            {**hit["_source"], "_index": hit["_index"], "_id": hit["_id"]}
            for hit in response["hits"]["hits"]
        ]

        return {
            "events": events,
            "total": response["hits"]["total"]["value"],
            "query": es_query
        }

    except ConnectionError:
        logger.error("Elasticsearch connection error")
        return {"error": "Cannot connect to Elasticsearch"}
    except AuthenticationException:
        logger.error("Elasticsearch authentication failed")
        return {"error": "Elasticsearch authentication failed"}
    except Exception as e:
        logger.error(f"Error retrieving events: {str(e)}")
        return {"error": f"Error retrieving events: {str(e)}"}

# Tool 3: Prepare events for LLM analysis
@mcp_server.tool()
async def prepare_llm_analysis(events: List[Dict[str, Any]], query: Optional[str] = None,
                                 focus_areas: Optional[List[str]] = None) -> dict:
    """Format events for analysis by LLM with customizable focus areas. Deduplicate events
    based on specific fields for Sysmon event IDs 1, 3, 5, 7, 8, 10, 11."""
    try:
        # Remove duplicates using field-based deduplication
        unique_events = remove_duplicates(events)
        
        # Define chunk size
        CHUNK_SIZE = 10
        # Split unique events into chunks
        event_chunks = [unique_events[i:i + CHUNK_SIZE] for i in range(0, len(unique_events), CHUNK_SIZE)]
        
        default_focus = [
            "Suspicious process or network activities",
            "Unusual command executions",
            "Potential lateral movement",
            "Signs of privilege escalation",
            "Evidence of data exfiltration"
        ]
        focus = focus_areas if focus_areas else default_focus

        # Generate a prompt for each chunk
        analysis_prompts = []
        for chunk_index, chunk in enumerate(event_chunks, 1):
            formatted_events = json.dumps(chunk, indent=2)
            context = f"""
# Security Event Analysis Request

## Events
```json
{formatted_events}
```

## Analysis Request
Please analyze these Windows event logs and determine if they indicate any malicious activity.
Focus on:
{chr(10).join(f'- {area}' for area in focus)}

For suspicious activities, explain why they are concerning and provide recommendations.
"""

            if query:
                context += f"\n\nAdditional context or question: {query}\n"

            analysis_prompts.append(context)

        return {
            "analysis_prompts": analysis_prompts,
            "unique_event_count": len(unique_events),
            "original_event_count": len(events)
        }

    except Exception as e:
        logger.error(f"Error preparing analysis: {str(e)}")
        return {"error": f"Error preparing analysis: {str(e)}"}

# Tool 4: Get event IDs
@mcp_server.tool()
async def get_event_ids(provider_name: Optional[str] = None, start_time: Optional[str] = None,
                        end_time: Optional[str] = None, agg_size: int = 10000) -> dict:
    """Get all event IDs, optionally filtered by provider name and time range.
    Defaults to events from the last 2 days if no time range is specified."""
    try:
        query = {
            "size": 0,
            "aggs": {
                "event_ids": {
                    "terms": {
                        "field": "winlog.event_id.keyword",
                        "size": agg_size,
                        "order": {"_key": "asc"}
                    }
                }
            }
        }

        # Build query filters
        if provider_name or start_time or end_time:
            query["query"] = {"bool": {"filter": []}}
            if provider_name:
                query["query"]["bool"]["filter"].append({
                    "term": {"winlog.provider_name.keyword": provider_name}
                })

        # Add time range filter (default to last 2 days if not specified)
        time_range = {"range": {"@timestamp": {}}}
        if start_time:
            time_range["range"]["@timestamp"]["gte"] = start_time
        else:
            time_range["range"]["@timestamp"]["gte"] = "now-7d"
        if end_time:
            time_range["range"]["@timestamp"]["lte"] = end_time
        else:
            time_range["range"]["@timestamp"]["lte"] = "now"
        query["query"]["bool"]["filter"].append(time_range)

        response = es.search(index="winlogbeat-*", body=query)
        event_ids = [bucket["key"] for bucket in response["aggregations"]["event_ids"]["buckets"]]

        return {"event_ids": event_ids, "count": len(event_ids)}

    except ConnectionError:
        logger.error("Elasticsearch connection error")
        return {"error": "Cannot connect to Elasticsearch"}
    except AuthenticationException:
        logger.error("Elasticsearch authentication failed")
        return {"error": "Elasticsearch authentication failed"}
    except Exception as e:
        logger.error(f"Error retrieving event IDs: {str(e)}")
        return {"error": f"Error retrieving event IDs: {str(e)}"}

# Tool 5: Get providers
@mcp_server.tool()
async def get_providers() -> dict:
    """Get all event provider names."""
    try:
        query = {
            "size": 0,
            "aggs": {
                "providers": {
                    "terms": {
                        "field": "winlog.provider_name.keyword",
                        "size": 10000
                    }
                }
            }
        }

        response = es.search(index="winlogbeat-*", body=query)
        providers = [bucket["key"] for bucket in response["aggregations"]["providers"]["buckets"]]

        return {"providers": providers, "count": len(providers)}

    except ConnectionError:
        logger.error("Elasticsearch connection error")
        return {"error": "Cannot connect to Elasticsearch"}
    except AuthenticationException:
        logger.error("Elasticsearch authentication failed")
        return {"error": "Elasticsearch authentication failed"}
    except Exception as e:
        logger.error(f"Error retrieving providers: {str(e)}")
        return {"error": f"Error retrieving providers: {str(e)}"}

# Tool 6: Health check
@mcp_server.tool()
async def health_check() -> dict:
    """Check the health of the MCP server and Elasticsearch connection."""
    try:
        es_health = es.cluster.health()
        
        # Check threat intel API health
        try:
            ti_response = requests.get(f"{THREAT_INTEL_URL}/health")
            ti_status = "ok" if ti_response.status_code == 200 else "error"
            ti_details = ti_response.json() if ti_response.status_code == 200 else {"error": f"Status code: {ti_response.status_code}"}
        except Exception as e:
            ti_status = "error"
            ti_details = {"error": str(e)}
        
        return {
            "status": "ok",
            "elasticsearch": es_health['status'],
            "threat_intel": {
                "status": ti_status,
                "details": ti_details
            },
            "version": "1.1.0"
        }
    except ConnectionError:
        logger.error("Elasticsearch connection error")
        return {"error": "Cannot connect to Elasticsearch"}
    except AuthenticationException:
        logger.error("Elasticsearch authentication failed")
        return {"error": "Elasticsearch authentication failed"}
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {"status": "error", "message": str(e)}

# Tool 7: Keyword search
@mcp_server.tool()
async def search_events(keyword: str, host_name: Optional[str] = None, start_time: Optional[str] = None,
                        end_time: Optional[str] = None, size: int = 10) -> dict:
    """Search events by keyword in winlog.event_data and message fields with optional host name and time range filtering.
    Defaults to events from the last 2 days if no time range is specified."""
    try:
        es_query = {
            "bool": {
                "filter": [],
                "must": {
                    "query_string": {
                        "query": f"*{keyword}*",
                        "fields": ["winlog.event_data", "message"],
                        "analyze_wildcard": True
                    }
                }
            }
        }

        # Add host_name filter if provided
        if host_name:
            es_query["bool"]["filter"].append({"term": {"winlog.computer_name.keyword": host_name}})

        # Add time range filter (default to last 2 days if not specified)
        time_range = {"range": {"@timestamp": {}}}
        if start_time:
            time_range["range"]["@timestamp"]["gte"] = start_time
        else:
            time_range["range"]["@timestamp"]["gte"] = "now-7d"
        if end_time:
            time_range["range"]["@timestamp"]["lte"] = end_time
        else:
            time_range["range"]["@timestamp"]["lte"] = "now"
        es_query["bool"]["filter"].append(time_range)
        
        response = es.search(
            index="winlogbeat-*",
            body={
                "query": es_query,
                "size": size,
                "_source": ["winlog", "@timestamp", "message"],
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )

        events = [
            {**hit["_source"], "_index": hit["_index"], "_id": hit["_id"]}
            for hit in response["hits"]["hits"]
        ]

        return {
            "events": events,
            "total": response["hits"]["total"]["value"],
            "query": es_query
        }

    except ConnectionError:
        logger.error("Elasticsearch connection error")
        return {"error": "Cannot connect to Elasticsearch"}
    except AuthenticationException:
        logger.error("Elasticsearch authentication failed")
        return {"error": "Elasticsearch authentication failed"}
    except Exception as e:
        logger.error(f"Error retrieving events: {str(e)}")
        return {"error": f"Error retrieving events: {str(e)}"}

# Tool 8: Enrich events with threat intelligence
@mcp_server.tool()
async def enrich_events_with_ti(event_ids: List[str]) -> dict:
    """Enrich events with threat intelligence data from external sources."""
    try:
        # First retrieve the events from Elasticsearch
        events = []
        for event_id in event_ids:
            try:
                result = es.get(index="winlogbeat-*", id=event_id)
                if result["found"]:
                    events.append({**result["_source"], "_id": result["_id"]})
            except Exception as e:
                logger.error(f"Error fetching event {event_id}: {str(e)}")
                continue
        
        if not events:
            return {"error": "No events found with the provided IDs"}
        
        # Call the threat intelligence API to enrich the events
        try:
            response = requests.post(
                f"{THREAT_INTEL_URL}/enrich_events",
                params={"event_ids": event_ids}
            )
            
            if response.status_code != 200:
                return {"error": f"Threat intelligence API error: {response.text}"}
            
            ti_data = response.json()
            
            return {
                "events": events,
                "threat_intel": ti_data,
                "enriched_count": len(events)
            }
            
        except Exception as e:
            logger.error(f"Error calling threat intelligence API: {str(e)}")
            return {"error": f"Error calling threat intelligence API: {str(e)}"}
        
    except Exception as e:
        logger.error(f"Error enriching events: {str(e)}")
        return {"error": f"Error enriching events: {str(e)}"}

# Tool 9: Look up specific IOC
@mcp_server.tool()
async def lookup_ioc(indicator: str, indicator_type: str) -> dict:
    """Look up a specific indicator of compromise (IOC) in threat intelligence sources."""
    try:
        if not indicator:
            return {"error": "No indicator provided"}
        
        if indicator_type not in ["ip", "domain", "file_hash"]:
            return {"error": "Invalid indicator type. Must be one of: ip, domain, file_hash"}
        
        # Call the threat intelligence API
        try:
            response = requests.post(
                f"{THREAT_INTEL_URL}/lookup_ioc",
                json={"indicator": indicator, "indicator_type": indicator_type}
            )
            
            if response.status_code != 200:
                return {"error": f"Threat intelligence API error: {response.text}"}
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Error calling threat intelligence API: {str(e)}")
            return {"error": f"Error calling threat intelligence API: {str(e)}"}
        
    except Exception as e:
        logger.error(f"Error looking up IOC: {str(e)}")
        return {"error": f"Error looking up IOC: {str(e)}"}

# Tool 10: Search for events related to an IOC
@mcp_server.tool()
async def search_events_by_ioc(indicator: str, indicator_type: str, 
                             start_time: Optional[str] = None, end_time: Optional[str] = None) -> dict:
    """Search for events related to a specific indicator of compromise (IOC)."""
    try:
        if not indicator:
            return {"error": "No indicator provided"}
        
        if indicator_type not in ["ip", "domain", "file_hash"]:
            return {"error": "Invalid indicator type. Must be one of: ip, domain, file_hash"}
        
        # Call the threat intelligence API
        try:
            params = {
                "indicator": indicator,
                "indicator_type": indicator_type
            }
            
            if start_time:
                params["start_time"] = start_time
            if end_time:
                params["end_time"] = end_time
            
            response = requests.post(
                f"{THREAT_INTEL_URL}/search_related_events",
                params=params
            )
            
            if response.status_code != 200:
                return {"error": f"Threat intelligence API error: {response.text}"}
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Error calling threat intelligence API: {str(e)}")
            return {"error": f"Error calling threat intelligence API: {str(e)}"}
        
    except Exception as e:
        logger.error(f"Error searching events by IOC: {str(e)}")
        return {"error": f"Error searching events by IOC: {str(e)}"}

# Tool 11: Hunt for IOC patterns
@mcp_server.tool()
async def hunt_for_ioc_patterns(ioc_list: List[Dict[str, str]], start_time: Optional[str] = None,
                               end_time: Optional[str] = None, host_name: Optional[str] = None) -> dict:
    """Hunt for patterns of IOCs across events."""
    try:
        if not ioc_list:
            return {"error": "No IOCs provided"}
        
        # Validate IOC list format
        for ioc in ioc_list:
            if not isinstance(ioc, dict) or "indicator" not in ioc or "indicator_type" not in ioc:
                return {"error": "Invalid IOC format. Each IOC must be a dict with 'indicator' and 'indicator_type' keys"}
            
            if ioc["indicator_type"] not in ["ip", "domain", "file_hash"]:
                return {"error": f"Invalid indicator type: {ioc['indicator_type']}. Must be one of: ip, domain, file_hash"}
        
        # Call the threat intelligence API
        try:
            params = {}
            if start_time:
                params["start_time"] = start_time
            if end_time:
                params["end_time"] = end_time
            if host_name:
                params["host_name"] = host_name
            
            response = requests.post(
                f"{THREAT_INTEL_URL}/hunt_for_ioc_patterns",
                json=ioc_list,
                params=params
            )
            
            if response.status_code != 200:
                return {"error": f"Threat intelligence API error: {response.text}"}
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Error calling threat intelligence API: {str(e)}")
            return {"error": f"Error calling threat intelligence API: {str(e)}"}
        
    except Exception as e:
        logger.error(f"Error hunting for IOC patterns: {str(e)}")
        return {"error": f"Error hunting for IOC patterns: {str(e)}"}

# Tool 12: Generate RAG-based threat analysis
@mcp_server.tool()
async def generate_threat_analysis(event_ids: List[str]) -> dict:
    """Generate a RAG-based threat analysis for the given events."""
    try:
        if not event_ids:
            return {"error": "No event IDs provided"}
        
        # Call the threat intelligence API
        try:
            response = requests.post(
                f"{THREAT_INTEL_URL}/generate_rag_summary",
                json=event_ids
            )
            
            if response.status_code != 200:
                return {"error": f"Threat intelligence API error: {response.text}"}
            
            return response.json()
            
        except Exception as e:
            logger.error(f"Error calling threat intelligence API: {str(e)}")
            return {"error": f"Error calling threat intelligence API: {str(e)}"}
        
    except Exception as e:
        logger.error(f"Error generating threat analysis: {str(e)}")
        return {"error": f"Error generating threat analysis: {str(e)}"}

# Tool 13: Extract IOCs from events
@mcp_server.tool()
async def extract_iocs_from_events(event_ids: List[str]) -> dict:
    """Extract potential indicators of compromise (IOCs) from the given events."""
    try:
        if not event_ids:
            return {"error": "No event IDs provided"}
        
        # First retrieve the events from Elasticsearch
        events = []
        for event_id in event_ids:
            try:
                result = es.get(index="winlogbeat-*", id=event_id)
                if result["found"]:
                    events.append({**result["_source"], "_id": result["_id"]})
            except Exception as e:
                logger.error(f"Error fetching event {event_id}: {str(e)}")
                continue
        
        if not events:
            return {"error": "No events found with the provided IDs"}
        
        # Define regex patterns for IOC extraction
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z]\b'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        import re
        
        # Extract IOCs from events
        iocs = {
            "ips": [],
            "domains": [],
            "file_hashes": [],
            "file_paths": [],
            "registry_keys": []
        }
        
        for event in events:
            # Process event data fields
            if "winlog" in event:
                for field in ["message", "event_data", "task", "description"]:
                    if field in event["winlog"]:
                        text = str(event["winlog"][field])
                        
                        # Extract IPs
                        ips = re.findall(ip_pattern, text)
                        for ip in ips:
                            if ip not in iocs["ips"]:
                                iocs["ips"].append(ip)
                        
                        # Extract domains
                        domains = re.findall(domain_pattern, text)
                        for domain in domains:
                            if domain not in iocs["domains"]:
                                iocs["domains"].append(domain)
                        
                        # Extract hashes
                        md5s = re.findall(md5_pattern, text)
                        sha1s = re.findall(sha1_pattern, text)
                        sha256s = re.findall(sha256_pattern, text)
                        
                        for h in md5s + sha1s + sha256s:
                            if h not in iocs["file_hashes"]:
                                iocs["file_hashes"].append(h)
                
                # Look for process information
                if "event_data" in event["winlog"]:
                    event_data = event["winlog"]["event_data"]
                    
                    # Extract file paths
                    for field in ["Image", "ImagePath", "TargetFilename", "SourceImage", "TargetImage"]:
                        if field in event_data:
                            path = event_data[field]
                            if path and path not in iocs["file_paths"]:
                                iocs["file_paths"].append(path)
                    
                    # Extract registry keys
                    for field in ["TargetObject", "ObjectName"]:
                        if field in event_data and isinstance(event_data[field], str) and event_data[field].startswith("HKEY_"):
                            key = event_data[field]
                            if key and key not in iocs["registry_keys"]:
                                iocs["registry_keys"].append(key)
        
        return {
            "event_count": len(events),
            "extracted_iocs": iocs,
            "ioc_counts": {
                "ips": len(iocs["ips"]),
                "domains": len(iocs["domains"]),
                "file_hashes": len(iocs["file_hashes"]),
                "file_paths": len(iocs["file_paths"]),
                "registry_keys": len(iocs["registry_keys"])
            }
        }
        
    except Exception as e:
        logger.error(f"Error extracting IOCs: {str(e)}")
        return {"error": f"Error extracting IOCs: {str(e)}"}

if __name__ == "__main__":
    mcp_server.run(transport='stdio')
