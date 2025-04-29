import os
import json
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Query
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, AuthenticationException
import requests
import logging
from datetime import datetime, timedelta
from pydantic import BaseModel
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='threat_intel_server.log'
)
logger = logging.getLogger("threat-intel-server")

# Configuration for Elasticsearch and threat intelligence APIs
es_host = os.getenv("ES_HOST", "localhost")
es_port = int(os.getenv("ES_PORT", "9200"))
es_user = os.getenv("ES_USER", "")
es_password = os.getenv("ES_PASSWORD", "")
vtotal_api_key = os.getenv("VTOTAL_API_KEY", "")
alienvault_api_key = os.getenv("ALIENVAULT_API_KEY", "")

# Initialize Elasticsearch client
try:
    if es_user and es_password:
        es = Elasticsearch(
            f"http://{es_host}:{es_port}",
            basic_auth=(es_user, es_password),
        )
    else:
        es = Elasticsearch(f"http://{es_host}:{es_port}")
except Exception as e:
    logger.error(f"Failed to initialize Elasticsearch client: {str(e)}")
    raise

# Initialize FastAPI
app = FastAPI(title="MCP Threat Intelligence Tool")

# Models for request/response
class ThreatIntelEnrichmentRequest(BaseModel):
    event_ids: List[str] = []
    ips: List[str] = []
    domains: List[str] = []
    file_hashes: List[str] = []
    event_sources: List[str] = []

class IOCLookupRequest(BaseModel):
    indicator: str
    indicator_type: str  # ip, domain, file_hash, etc.

class ThreatIntelReport(BaseModel):
    matched_iocs: Dict[str, Any] = {}
    related_threats: List[Dict[str, Any]] = []
    risk_score: int = 0
    context: Dict[str, Any] = {}

# Helper functions
def extract_iocs_from_events(events: List[Dict]) -> Dict[str, List[str]]:
    """Extract potential IOCs from event data"""
    iocs = {
        "ips": [],
        "domains": [],
        "file_hashes": [],
        "file_paths": [],
        "registry_keys": []
    }
    
    # IP regex pattern
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    
    # Domain regex pattern - simplistic but works for most cases
    domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z]\b'
    
    # Common hash formats (MD5, SHA1, SHA256)
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
    
    for event in events:
        # Process event data fields
        for field in ["message", "event_data", "task", "description"]:
            if field in event.get("winlog", {}):
                text = str(event["winlog"][field])
                
                # Extract IPs
                ips = re.findall(ip_pattern, text)
                iocs["ips"].extend([ip for ip in ips if ip not in iocs["ips"]])
                
                # Extract domains
                domains = re.findall(domain_pattern, text)
                iocs["domains"].extend([domain for domain in domains if domain not in iocs["domains"]])
                
                # Extract hashes
                md5s = re.findall(md5_pattern, text)
                sha1s = re.findall(sha1_pattern, text)
                sha256s = re.findall(sha256_pattern, text)
                
                iocs["file_hashes"].extend([h for h in md5s + sha1s + sha256s if h not in iocs["file_hashes"]])
        
        # Look for process information
        if "event_data" in event.get("winlog", {}):
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
    
    return iocs

def query_virustotal(indicator: str, indicator_type: str) -> Dict:
    """Query VirusTotal API for given indicator"""
    if not vtotal_api_key:
        return {"error": "VirusTotal API key not configured"}
    
    base_url = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": vtotal_api_key}
    
    endpoint = ""
    if indicator_type == "ip":
        endpoint = f"/ip_addresses/{indicator}"
    elif indicator_type == "domain":
        endpoint = f"/domains/{indicator}"
    elif indicator_type == "file_hash":
        endpoint = f"/files/{indicator}"
    else:
        return {"error": "Unsupported indicator type"}
    
    try:
        response = requests.get(f"{base_url}{endpoint}", headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"VirusTotal API error: {response.status_code}", "details": response.text}
    except Exception as e:
        return {"error": f"VirusTotal API exception: {str(e)}"}

def query_alienvault_otx(indicator: str, indicator_type: str) -> Dict:
    """Query AlienVault OTX API for given indicator"""
    if not alienvault_api_key:
        return {"error": "AlienVault API key not configured"}
    
    base_url = "https://otx.alienvault.com/api/v1"
    headers = {"X-OTX-API-KEY": alienvault_api_key}
    
    section = ""
    if indicator_type == "ip":
        section = "IPv4"
    elif indicator_type == "domain":
        section = "domain"
    elif indicator_type == "file_hash":
        section = "file"
    else:
        return {"error": "Unsupported indicator type"}
    
    try:
        response = requests.get(f"{base_url}/indicators/{section}/{indicator}/general", headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"AlienVault API error: {response.status_code}", "details": response.text}
    except Exception as e:
        return {"error": f"AlienVault API exception: {str(e)}"}

def calculate_risk_score(intel_data: Dict) -> int:
    """Calculate a simple risk score based on threat intelligence data"""
    score = 0
    
    # Process VirusTotal data
    if "virustotal" in intel_data:
        vt_data = intel_data["virustotal"]
        
        # Check for malicious verdicts
        if "data" in vt_data and "attributes" in vt_data["data"]:
            attrs = vt_data["data"]["attributes"]
            
            # For files
            if "last_analysis_stats" in attrs:
                stats = attrs["last_analysis_stats"]
                if "malicious" in stats:
                    # Add 10 points for each engine that found it malicious, up to 50
                    score += min(stats["malicious"] * 10, 50)
            
            # For domains/IPs
            if "reputation" in attrs:
                reputation = attrs["reputation"]
                if reputation < 0:
                    # Add points based on negative reputation
                    score += min(abs(reputation), 30)
    
    # Process AlienVault data
    if "alienvault" in intel_data:
        av_data = intel_data["alienvault"]
        
        # Check pulse count
        if "pulse_info" in av_data and "count" in av_data["pulse_info"]:
            # Add 5 points for each pulse, up to 40
            score += min(av_data["pulse_info"]["count"] * 5, 40)
    
    # Cap the score at 100
    return min(score, 100)

def find_related_mitre_techniques(intel_data: Dict) -> List[Dict]:
    """Extract MITRE ATT&CK techniques mentioned in threat intelligence"""
    techniques = []
    
    # Look for techniques in AlienVault data
    if "alienvault" in intel_data and "pulse_info" in intel_data["alienvault"]:
        for pulse in intel_data["alienvault"]["pulse_info"].get("pulses", []):
            for tag in pulse.get("tags", []):
                # Look for ATT&CK technique IDs
                if tag.startswith("T") and re.match(r'T\d{4}(\.\d{3})?', tag):
                    technique = {
                        "id": tag,
                        "name": "",  # Would need a mapping of technique IDs to names
                        "source": "AlienVault OTX",
                        "reference": pulse.get("name", "")
                    }
                    if technique not in techniques:
                        techniques.append(technique)
    
    return techniques

@app.get("/")
def read_root():
    return {"message": "MCP Threat Intelligence Tool"}

@app.get("/health")
def health_check():
    """Check the health of the service and its dependencies"""
    try:
        # Check ES connection
        es_health = es.cluster.health()
        
        # Check threat intel API keys
        intel_sources = {
            "virustotal": bool(vtotal_api_key),
            "alienvault_otx": bool(alienvault_api_key)
        }
        
        return {
            "status": "ok",
            "elasticsearch": es_health["status"],
            "threat_intel_sources": intel_sources
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {"status": "error", "message": str(e)}

@app.post("/enrich_events")
def enrich_events(event_ids: List[str] = Query(None)):
    """Enrich events with threat intelligence"""
    if not event_ids:
        raise HTTPException(status_code=400, detail="No event IDs provided")
    
    # Get events from Elasticsearch
    events = []
    for event_id in event_ids:
        try:
            result = es.get(index="winlogbeat-*", id=event_id)
            if result["found"]:
                events.append(result["_source"])
        except Exception as e:
            logger.error(f"Error fetching event {event_id}: {str(e)}")
    
    if not events:
        raise HTTPException(status_code=404, detail="No events found with the provided IDs")
    
    # Extract IOCs from events
    iocs = extract_iocs_from_events(events)
    
    # Query threat intelligence for extracted IOCs
    intel_results = {
        "ips": {},
        "domains": {},
        "file_hashes": {}
    }
    
    # Process IPs
    for ip in iocs["ips"][:10]:  # Limit to 10 IPs to avoid API rate limits
        vt_data = query_virustotal(ip, "ip")
        av_data = query_alienvault_otx(ip, "ip")
        
        intel_results["ips"][ip] = {
            "virustotal": vt_data,
            "alienvault": av_data
        }
    
    # Process domains
    for domain in iocs["domains"][:10]:
        vt_data = query_virustotal(domain, "domain")
        av_data = query_alienvault_otx(domain, "domain")
        
        intel_results["domains"][domain] = {
            "virustotal": vt_data,
            "alienvault": av_data
        }
    
    # Process file hashes
    for file_hash in iocs["file_hashes"][:10]:
        vt_data = query_virustotal(file_hash, "file_hash")
        av_data = query_alienvault_otx(file_hash, "file_hash")
        
        intel_results["file_hashes"][file_hash] = {
            "virustotal": vt_data,
            "alienvault": av_data
        }
    
    # Calculate risk scores and find related techniques
    enriched_results = {
        "events": events,
        "extracted_iocs": iocs,
        "intel_results": intel_results,
        "risk_scores": {},
        "mitre_techniques": []
    }
    
    # Calculate risk scores for each IOC type
    for ioc_type in ["ips", "domains", "file_hashes"]:
        for indicator, data in intel_results[ioc_type].items():
            risk_score = calculate_risk_score(data)
            enriched_results["risk_scores"][indicator] = risk_score
            
            # Find related MITRE techniques
            techniques = find_related_mitre_techniques(data)
            for technique in techniques:
                if technique not in enriched_results["mitre_techniques"]:
                    enriched_results["mitre_techniques"].append(technique)
    
    # Calculate overall risk score
    if enriched_results["risk_scores"]:
        overall_risk = sum(enriched_results["risk_scores"].values()) / len(enriched_results["risk_scores"])
        enriched_results["overall_risk_score"] = min(int(overall_risk), 100)
    else:
        enriched_results["overall_risk_score"] = 0
    
    return enriched_results

@app.post("/lookup_ioc")
def lookup_ioc(request: IOCLookupRequest):
    """Look up a specific IOC against threat intelligence sources"""
    indicator = request.indicator
    indicator_type = request.indicator_type
    
    if not indicator:
        raise HTTPException(status_code=400, detail="No indicator provided")
    
    if indicator_type not in ["ip", "domain", "file_hash"]:
        raise HTTPException(status_code=400, detail="Invalid indicator type")
    
    # Query threat intelligence sources
    vt_data = query_virustotal(indicator, indicator_type)
    av_data = query_alienvault_otx(indicator, indicator_type)
    
    intel_data = {
        "virustotal": vt_data,
        "alienvault": av_data
    }
    
    # Calculate risk score
    risk_score = calculate_risk_score(intel_data)
    
    # Find related MITRE techniques
    mitre_techniques = find_related_mitre_techniques(intel_data)
    
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "intel_data": intel_data,
        "risk_score": risk_score,
        "mitre_techniques": mitre_techniques
    }

@app.post("/search_related_events")
def search_related_events(indicator: str, indicator_type: str, start_time: Optional[str] = None, end_time: Optional[str] = None):
    """Search for events related to a specific indicator"""
    if not indicator:
        raise HTTPException(status_code=400, detail="No indicator provided")
    
    # Set default time range if not provided
    if not start_time:
        start_time = (datetime.now() - timedelta(days=7)).isoformat()
    if not end_time:
        end_time = datetime.now().isoformat()
    
    # Build Elasticsearch query based on indicator type
    query = {
        "bool": {
            "must": [
                {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
            ]
        }
    }
    
    # Add indicator-specific search
    if indicator_type == "ip":
        query["bool"]["should"] = [
            {"match_phrase": {"winlog.event_data.SourceIp": indicator}},
            {"match_phrase": {"winlog.event_data.DestinationIp": indicator}},
            {"match_phrase": {"winlog.event_data.IpAddress": indicator}},
            {"match_phrase": {"message": indicator}}
        ]
    elif indicator_type == "domain":
        query["bool"]["should"] = [
            {"match_phrase": {"winlog.event_data.TargetServerName": indicator}},
            {"match_phrase": {"winlog.event_data.Hostname": indicator}},
            {"match_phrase": {"message": indicator}}
        ]
    elif indicator_type == "file_hash":
        query["bool"]["should"] = [
            {"match_phrase": {"winlog.event_data.Hashes": indicator}},
            {"match_phrase": {"message": indicator}}
        ]
    else:
        raise HTTPException(status_code=400, detail="Invalid indicator type")
    
    # At least one "should" clause must match
    query["bool"]["minimum_should_match"] = 1
    
    # Execute search
    try:
        result = es.search(
            index="winlogbeat-*",
            body={
                "query": query,
                "size": 100,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        
        # Process results
        events = []
        for hit in result["hits"]["hits"]:
            events.append({
                "event_id": hit["_id"],
                "timestamp": hit["_source"].get("@timestamp"),
                "host_name": hit["_source"].get("host", {}).get("name"),
                "event_id": hit["_source"].get("winlog", {}).get("event_id"),
                "provider_name": hit["_source"].get("winlog", {}).get("provider_name"),
                "record_id": hit["_source"].get("winlog", {}).get("record_id"),
                "event_data": hit["_source"].get("winlog", {}).get("event_data", {})
            })
        
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "time_range": {"start": start_time, "end": end_time},
            "total_hits": result["hits"]["total"]["value"],
            "events": events
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching Elasticsearch: {str(e)}")

@app.post("/hunt_for_ioc_patterns")
def hunt_for_ioc_patterns(
    ioc_list: List[Dict[str, str]], 
    start_time: Optional[str] = None, 
    end_time: Optional[str] = None,
    host_name: Optional[str] = None
):
    """Hunt for patterns of IOCs across events"""
    if not ioc_list:
        raise HTTPException(status_code=400, detail="No IOCs provided")
    
    # Set default time range if not provided
    if not start_time:
        start_time = (datetime.now() - timedelta(days=7)).isoformat()
    if not end_time:
        end_time = datetime.now().isoformat()
    
    # Build query
    must_clauses = [
        {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
    ]
    
    if host_name:
        must_clauses.append({"match": {"host.name": host_name}})
    
    # Build should clauses for each IOC
    should_clauses = []
    for ioc in ioc_list:
        indicator = ioc.get("indicator")
        indicator_type = ioc.get("indicator_type")
        
        if not indicator or not indicator_type:
            continue
        
        if indicator_type == "ip":
            should_clauses.extend([
                {"match_phrase": {"winlog.event_data.SourceIp": indicator}},
                {"match_phrase": {"winlog.event_data.DestinationIp": indicator}},
                {"match_phrase": {"winlog.event_data.IpAddress": indicator}},
                {"match_phrase": {"message": indicator}}
            ])
        elif indicator_type == "domain":
            should_clauses.extend([
                {"match_phrase": {"winlog.event_data.TargetServerName": indicator}},
                {"match_phrase": {"winlog.event_data.Hostname": indicator}},
                {"match_phrase": {"message": indicator}}
            ])
        elif indicator_type == "file_hash":
            should_clauses.extend([
                {"match_phrase": {"winlog.event_data.Hashes": indicator}},
                {"match_phrase": {"message": indicator}}
            ])
    
    query = {
        "bool": {
            "must": must_clauses,
            "should": should_clauses,
            "minimum_should_match": 1
        }
    }
    
    # Execute search
    try:
        result = es.search(
            index="winlogbeat-*",
            body={
                "query": query,
                "size": 100,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        )
        
        # Process results
        events = []
        for hit in result["hits"]["hits"]:
            events.append({
                "event_id": hit["_id"],
                "timestamp": hit["_source"].get("@timestamp"),
                "host_name": hit["_source"].get("host", {}).get("name"),
                "event_id": hit["_source"].get("winlog", {}).get("event_id"),
                "provider_name": hit["_source"].get("winlog", {}).get("provider_name"),
                "record_id": hit["_source"].get("winlog", {}).get("record_id"),
                "event_data": hit["_source"].get("winlog", {}).get("event_data", {})
            })
        
        # Group events by host
        hosts_timeline = {}
        for event in events:
            host = event["host_name"]
            if host not in hosts_timeline:
                hosts_timeline[host] = []
            hosts_timeline[host].append(event)
        
        # Sort events by timestamp within each host
        for host in hosts_timeline:
            hosts_timeline[host].sort(key=lambda x: x["timestamp"])
        
        return {
            "ioc_count": len(ioc_list),
            "time_range": {"start": start_time, "end": end_time},
            "total_hits": result["hits"]["total"]["value"],
            "events": events,
            "hosts_timeline": hosts_timeline
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching Elasticsearch: {str(e)}")

@app.post("/generate_rag_summary")
def generate_rag_summary(event_ids: List[str]):
    """Generate a RAG-based summary of events with threat intelligence context"""
    if not event_ids:
        raise HTTPException(status_code=400, detail="No event IDs provided")
    
    # Get events from Elasticsearch
    events = []
    for event_id in event_ids:
        try:
            result = es.get(index="winlogbeat-*", id=event_id)
            if result["found"]:
                events.append(result["_source"])
        except Exception as e:
            logger.error(f"Error fetching event {event_id}: {str(e)}")
    
    if not events:
        raise HTTPException(status_code=404, detail="No events found with the provided IDs")
    
    # Extract IOCs from events
    iocs = extract_iocs_from_events(events)
    
    # Format events for analysis
    formatted_events = []
    for event in events:
        formatted_event = {
            "timestamp": event.get("@timestamp"),
            "host": event.get("host", {}).get("name"),
            "event_id": event.get("winlog", {}).get("event_id"),
            "provider": event.get("winlog", {}).get("provider_name"),
            "record_id": event.get("winlog", {}).get("record_id"),
            "message": event.get("message", "")
        }
        
        # Add event data
        if "event_data" in event.get("winlog", {}):
            formatted_event["event_data"] = event["winlog"]["event_data"]
        
        formatted_events.append(formatted_event)
    
    # Here we would normally call an LLM for RAG analysis
    # For now, we'll just return the structured data
    
    return {
        "events": formatted_events,
        "extracted_iocs": iocs,
        "rag_analysis": {
            "summary": "This would contain the RAG-generated summary",
            "potential_threats": ["This would contain potential threats identified by RAG"],
            "recommendations": ["This would contain recommendations from RAG"]
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
