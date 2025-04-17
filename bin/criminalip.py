#!/usr/bin/env python3
# coding=utf-8

import sys
import json
import requests
import re
from datetime import datetime
import logging
import logging.handlers
import os 
import splunk

app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
lib_path = os.path.join(app_root, 'lib')
sys.path.append(lib_path)

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option
import splunklib.client as client
import time
from functools import wraps

def cache_handler(func):
    @wraps(func)
    def wrapper(self, ip_address):
        try:
            key = f"criminalip_{ip_address}"
            cached_result = self.service.kvstore[self.kv_collection].data.query(
                query=json.dumps({
                    "_key": key,
                    "timestamp": {"$gt": time.time() - self.cache_duration}  
                })
            )
            
            if cached_result:
                self.debug(f"Get Cache result: {ip_address}")
                return json.loads(cached_result[0]['api_result'])
                
            result = func(self, ip_address)
            
            if result:
                data = {
                    "_key": key,
                    "timestamp": time.time(),
                    "ip_address": ip_address,
                    "api_result": json.dumps(result),
                    "update_time": datetime.now().isoformat()
                }
                
                try:
                    self.service.kvstore[self.kv_collection].data.delete(query=json.dumps({"_key": key}))
                except:
                    pass  
                    
                self.service.kvstore[self.kv_collection].data.insert(json.dumps(data))
                self.debug(f"Cached result for IP: {ip_address}")
            
            return result
            
        except Exception as e:
            self.debug(f"Cache operation failed for IP {ip_address}: {str(e)}")
            if 'result' in locals():
                return result
            return func(self, ip_address)
            
    return wrapper

def error_handler(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as e:
            self.debug(f"Error in {func.__name__}: {str(e)}")
            return None
    return wrapper

class DebugMixin:
    def setup_debug(self):
        self.debug_logger = logging.getLogger(f"splunk.criminal_ip_search")
        self.debug_logger.setLevel(logging.DEBUG)
        SPLUNK_HOME = os.environ.get('SPLUNK_HOME')
        LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
        LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
        LOGGING_STANZA_NAME = 'python'
        LOGGING_FILE_NAME = 'criminal_ip_search.log'
        BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
        LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
        splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a') 
        splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
        self.debug_logger.addHandler(splunk_log_handler)
        splunk.setupSplunkLogger(self.debug_logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
        return self.debug_logger
    
    def debug(self, message, data=None):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        debug_info = {
            'timestamp': timestamp,
            'message': message
        }
        
        if data is not None:
            if isinstance(data, (dict, list)):
                debug_info['data'] = data
            else:
                debug_info['data'] = str(data)
                
        self.debug_logger.debug(json.dumps(debug_info, indent=2, ensure_ascii=False))


@Configuration()
class CriminalIPAPIData(StreamingCommand, DebugMixin):
    """
    Fetch IP information from CriminalIP API.
    
    ##Syntax
    | criminalip ip=<ip_address>
    | <search_command> | criminalip ip_field=<field_containing_ip>
    
    ##Description
    Retrieves detailed IP information including WHOIS data and security reports from CriminalIP API.
    Can be used either with a direct IP input or with a field containing IP addresses from a previous search.
    """

    ip_address = Option(
        doc='''
        **Syntax:** **ip=***<ip_address>*
        **Description:** Single IP address to query''',
        require=False,
        default=None
    )
    
    REPORT_URL = "https://api.criminalip.io/v1/asset/ip/report/summary"
    SUMMARY_URL = "https://api.criminalip.io/v1/asset/ip/summary"
    
    def prepare(self):
        """Get API key from Splunk configuration"""
        try:
            for passwd in self.service.storage_passwords:
                if passwd.username == "cip_api_key":
                    self.api_key = passwd.clear_password
                    break
            
            # Verify we got the key
            if not self.api_key:
                self.error_exit(None, "No API key found for Criminal IP. Re-run the app setup.")
                    
        except Exception as e:
            self.debug(f"Error retrieving API key: {str(e)}")
            raise Exception("Failed to retrieve API key. Please check the configuration.")

    def __init__(self):
        super().__init__()
        self.setup_debug()
        self.kv_collection = "criminalip_results"
        self.cache_duration = 86400
        self.api_key = None
        
    @property
    def headers(self):
        """Generate headers with API key"""
        if not self.api_key:
            raise Exception("API key not initialized")
        return {"x-api-key": self.api_key}

    def validate_ip(self, ip_address):
        """Validate IP address format"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, ip_address))
    
    def is_private_ip(self, ip):
        """Check if IP address is private"""
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            return True
            
        # Private IP ranges
        if ip_parts[0] == '10':  # 10.0.0.0 - 10.255.255.255
            return True
        elif ip_parts[0] == '172' and 16 <= int(ip_parts[1]) <= 31:  # 172.16.0.0 - 172.31.255.255
            return True
        elif ip_parts[0] == '192' and ip_parts[1] == '168':  # 192.168.0.0 - 192.168.255.255
            return True
        elif ip_parts[0] == '127':  # localhost
            return True
        return False
    
    @error_handler
    @cache_handler
    def fetch_ip_data(self, ip_address):
        """Fetch data from CriminalIP API"""
        params = {"ip": ip_address}
        self.debug(f"Fetching data for IP", {'ip': ip_address})

        # Report API
        report_response = requests.get(
            self.REPORT_URL, 
            headers=self.headers, 
            params=params, 
            timeout=30
        )
        report_response.raise_for_status()
        report_data = report_response.json()

        # Summary API
        summary_response = requests.get(
            self.SUMMARY_URL, 
            headers=self.headers, 
            params=params, 
            timeout=30
        )
        summary_response.raise_for_status()
        summary_data = summary_response.json()

        return self.process_api_response(report_data, summary_data)

       
    @error_handler
    def process_api_response(self, report_data, summary_data):
        """Process API response data"""
        def bool_to_string(value):
            if isinstance(value, bool):
                return 'True' if value else 'False'
            return value
        
        result = {
            'inbound_score': report_data['ip_scoring']['inbound'],
            'outbound_score': report_data['ip_scoring']['outbound'],
            'representative_domain' : report_data['summary']['connection']['representative_domain'],
            'ssl_certificate' : bool_to_string(report_data['summary']['connection']['ssl_certificate']),
            'connected_domains' : report_data['summary']['connection']['connected_domains'],
            'is_malicious': bool_to_string(report_data['ip_scoring']['is_malicious']),
            'issue': ', '.join(report_data['issue']),
            'special_issue': report_data['summary']['detection']['special_issue'],
            'tags': ', '.join(report_data['tags']),
            'tor': bool_to_string(report_data['summary']['detection']['tor_ip']),
            'vpn': bool_to_string(report_data['summary']['detection']['vpn_ip']),
            'proxy': bool_to_string(report_data['summary']['detection']['proxy_ip']),
            'hosting': bool_to_string(report_data['summary']['detection']['hosting_ip']),
            'mobile': bool_to_string(report_data['summary']['detection']['mobile_ip']),
            'cdn': bool_to_string(report_data['summary']['detection']['cdn_ip']),
            'scanner': bool_to_string(report_data['summary']['detection']['scanner_ip']),
            'anonymous_vpn': bool_to_string(report_data['summary']['detection']['anonymous_vpn_detection']),
            'abuse_record': report_data['summary']['security']['abuse_record'],
            'open_ports': report_data['summary']['security']['open_ports'],
            'vulnerabilities': report_data['summary']['security']['vulnerabilities'],
            'exploit_db': report_data['summary']['security']['exploit_db'],
            'policy_violation': report_data['summary']['security']['policy_violation'],
            'remote_address': bool_to_string(report_data['summary']['security']['remote_address']),
            'network_device': bool_to_string(report_data['summary']['security']['network_device']),
            'admin_page': bool_to_string(report_data['summary']['security']['admin_page']),
            'invalid_ssl': bool_to_string(report_data['summary']['security']['invalid_ssl']),
            'has_real_ip': bool_to_string(report_data['summary']['dns_service']['real_ip']),
            'hostname' : report_data['summary']['connection']['hostname'],
            'country': summary_data.get('country'),
            'country_code': summary_data.get('country_code'),
            'region': summary_data.get('region'),
            'city': summary_data.get('city'),
            'isp': summary_data.get('isp'),
            'org_name': summary_data.get('org_name'),
            'as_no': summary_data.get('as_no'),
            'postal_code': summary_data.get('postal_code'),
            'latitude': summary_data.get('latitude'),
            'longitude': summary_data.get('longitude'),     
        }
        
        return result
    

    def create_event(self, data, event_type="info", error_message=None):
        """Create standardized event output"""
        event = {
            "_time": datetime.now().timestamp(),
            "type": event_type,
            "api_query_time": datetime.now().isoformat()
        }

        if event_type == "error":
            event.update({
                "error_message": error_message,
                "severity": "error"
            })
        else:
            event.update({
                "result": json.dumps(data, indent=2, ensure_ascii=False),
                "severity": "info"
            })

        return event

    def stream(self, records):
        self.prepare()
        
        if not self.api_key:
            yield self.create_event(None, "error", "API key is not configured")
            return

        if self.ip_address:
            if not self.validate_ip(self.ip_address):
                yield self.create_event(None, "error", f"Invalid IP address format: {self.ip_address}")
                return
            
            if self.is_private_ip(self.ip_address):
                yield self.create_event(None, "error", f"Invalid Search IP Address (Reason: Private IP Address)")
                return

            result = self.fetch_ip_data(self.ip_address)
            if result:
                record = {}
                record['ip_address'] = self.ip_address
                for key, value in result.items():
                    record[key] = value
                yield record
            else:
                yield self.create_event(None, "error", f"Failed to fetch data for IP: {self.ip_address}")
            return

        results = []
        error_events = []
                
        for record in records:
            try:
                if 'ip_address' not in record:
                    error_events.append(self.create_event(None, "error", "No ip_address field in record"))
                    continue

                ip_address = record['ip_address']
                if not ip_address:
                    error_events.append(self.create_event(None, "error", "Empty IP address in record"))
                    continue

                if not self.validate_ip(ip_address):
                    error_events.append(self.create_event(None, "error", f"Invalid IP address format: {ip_address}"))
                    continue
                
                if self.is_private_ip(ip_address):
                    continue
                
                result = self.fetch_ip_data(ip_address)
                if result:
                    for key, value in result.items():
                        record[key] = value
                    results.append(record)
                else:
                    error_events.append(self.create_event(None, "error", f"Failed to fetch data for IP: {ip_address}"))
            
            except Exception as e:
                self.debug(f"Error processing record: {str(e)}")
                error_events.append(self.create_event(None, "error", f"Error processing record: {str(e)}"))

        
        sorted_results = sorted(results, key=lambda x: x.get('_time', 0), reverse=True)
        for result in sorted_results:
            yield result
dispatch(CriminalIPAPIData, sys.argv, sys.stdin, sys.stdout, __name__)