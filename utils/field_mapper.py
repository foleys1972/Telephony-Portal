#!/usr/bin/env python3
"""
Dynamic Field Mapping Utility for CSV Imports
"""

import csv
import os
from typing import Dict, List, Tuple, Optional

class FieldMapper:
    """Handles dynamic field mapping for CSV imports"""
    
    def __init__(self):
        # Define field definitions for each import type
        self.field_definitions = {
            'ddi': {
                'ddi_number': {
                    'required': True,
                    'description': 'DDI number (any format)',
                    'keywords': ['ddi number', 'ddi_number', 'ddi', 'number', 'extension', 'lineextension'],
                    'validation': lambda x: bool(x and x.strip())  # Just check it's not empty
                },
                'username': {
                    'required': False,
                    'description': 'User name / owner of the DDI',
                    'keywords': ['username', 'linename', 'user', 'name', 'owner']
                },
                'line_type': {
                    'required': False,
                    'description': 'Type of line (e.g., DDI)',
                    'keywords': ['line type', 'linetype', 'type', 'line_type']
                },
                'cisco_cluster': {
                    'required': False,
                    'description': 'Cisco call cluster',
                    'keywords': ['cisco cluster', 'cluster', 'cisco_cluster', 'cisco']
                },
                'tpo': {
                    'required': False,
                    'description': 'TPO (dropdown in UI)',
                    'keywords': ['tpo', 'tpo_owner', 'tpo owner', 'tpo_name', 'tpo name']
                },
                'tpo_dns_name': {
                    'required': False,
                    'description': 'TPO DNS Name',
                    'keywords': ['tpo dns name', 'tpodnsname', 'tpo_dns_name', 'tpo dns', 'dns name']
                },
                'voice_recording': {
                    'required': False,
                    'description': 'Voice recording setting',
                    'keywords': ['voice recording', 'voicerecording', 'recording', 'voice']
                },
                'place': {
                    'required': False,
                    'description': 'Place information',
                    'keywords': ['place']
                },
                'slots': {
                    'required': False,
                    'description': 'Slots information',
                    'keywords': ['slots']
                },
                'virtual_slot_start': {
                    'required': False,
                    'description': 'Virtual slot start information',
                    'keywords': ['virtual slot start', 'virtualslotstart', 'virtual_slot_start']
                },
                'virtual_slot_stop': {
                    'required': False,
                    'description': 'Virtual slot stop information',
                    'keywords': ['virtual slot stop', 'virtualslotstop', 'virtual_slot_stop']
                },
                'bt_system': {
                    'required': False,
                    'description': 'BT System',
                    'keywords': ['bt system', 'btsystem', 'bt', 'system']
                },
                'location': {
                    'required': False,
                    'description': 'Physical location',
                    'keywords': ['location']
                },
                'status': {
                    'required': False,
                    'description': 'Status (Active/Spare)',
                    'keywords': ['status']
                },
                'date_spare': {
                    'required': False,
                    'description': 'Date when marked as spare',
                    'keywords': ['date spare', 'datespare', 'date_spare', 'spare date']
                },
                'last_change': {
                    'required': False,
                    'description': 'Description of last change',
                    'keywords': ['last change', 'lastchange', 'last_change', 'change']
                }
            },
            'private_wire': {
                'record_no': {
                    'required': True,
                    'description': 'Unique record number',
                    'keywords': ['record_no', 'record', 'recordno', 'id']
                },
                'location': {
                    'required': False,
                    'description': 'Physical location',
                    'keywords': ['location']
                },
                'dc_locale': {
                    'required': False,
                    'description': 'DC Locale',
                    'keywords': ['dc_locale', 'dclocale', 'dc']
                },
                'vega_port': {
                    'required': False,
                    'description': 'Vega Port',
                    'keywords': ['vega_port', 'vegaport', 'vega', 'port']
                },
                'channel': {
                    'required': False,
                    'description': 'Channel',
                    'keywords': ['channel']
                },
                'bearer_no': {
                    'required': False,
                    'description': 'Bearer Number',
                    'keywords': ['bearer_no', 'bearerno', 'bearer']
                },
                'circuit_no': {
                    'required': False,
                    'description': 'Circuit Number',
                    'keywords': ['circuit_no', 'circuitno', 'circuit']
                },
                'back_up_bearer': {
                    'required': False,
                    'description': 'Backup Bearer',
                    'keywords': ['back_up_bearer', 'backup_bearer', 'backupbearer']
                },
                'cluster_name': {
                    'required': False,
                    'description': 'Cluster Name',
                    'keywords': ['cluster_name', 'clustername', 'cluster']
                },
                'tpo_name': {
                    'required': False,
                    'description': 'TPO Name',
                    'keywords': ['tpo_name', 'tponame', 'tpo']
                },
                'vega_hostname': {
                    'required': False,
                    'description': 'Vega Hostname',
                    'keywords': ['vega_hostname', 'vegahostname', 'hostname']
                },
                'back_up_vega_gw': {
                    'required': False,
                    'description': 'Backup Vega Gateway',
                    'keywords': ['back_up_vega_gw', 'backup_vega_gw', 'backupvegagw']
                },
                'vendor': {
                    'required': False,
                    'description': 'Vendor',
                    'keywords': ['vendor']
                },
                'pw_type': {
                    'required': False,
                    'description': 'Private Wire Type',
                    'keywords': ['pw_type', 'pwtype', 'pw', 'type']
                },
                'btt_slot': {
                    'required': False,
                    'description': 'BTT Slot',
                    'keywords': ['btt_slot', 'bttslot', 'btt']
                },
                'aor': {
                    'required': False,
                    'description': 'AOR',
                    'keywords': ['aor']
                },
                'a_or_b': {
                    'required': False,
                    'description': 'A or B designation',
                    'keywords': ['a_or_b', 'aorb', 'a or b']
                },
                'dedicated_country': {
                    'required': False,
                    'description': 'Dedicated Country',
                    'keywords': ['dedicated_country', 'dedicatedcountry', 'country']
                },
                'hsbc_main_user': {
                    'required': False,
                    'description': 'HSBC Main User',
                    'keywords': ['hsbc_main_user', 'hsbcmainuser', 'mainuser', 'user']
                },
                'employee_id': {
                    'required': False,
                    'description': 'Employee ID',
                    'keywords': ['employee_id', 'employeeid', 'empid']
                },
                'private_public': {
                    'required': False,
                    'description': 'Private or Public',
                    'keywords': ['private_public', 'privatepublic', 'private / public']
                },
                'line_label': {
                    'required': False,
                    'description': 'Line Label',
                    'keywords': ['line_label', 'linelabel', 'label']
                },
                'company_name': {
                    'required': False,
                    'description': 'Company Name',
                    'keywords': ['company_name', 'companyname', 'company']
                },
                'company_contact': {
                    'required': False,
                    'description': 'Company Contact',
                    'keywords': ['company_contact', 'companycontact', 'contact']
                },
                'company_email': {
                    'required': False,
                    'description': 'Company Email',
                    'keywords': ['company_email', 'companyemail', 'email']
                },
                'vr_yn': {
                    'required': False,
                    'description': 'VR Yes/No',
                    'keywords': ['vr_yn', 'vryn', 'vr', 'vr y / n']
                },
                'snow_ref': {
                    'required': False,
                    'description': 'SNOW Reference',
                    'keywords': ['snow_ref', 'snowref', 'snow']
                }
            },
            'turret': {
                'mac_address': {
                    'required': True,
                    'description': 'Primary MAC Address (MAC 1)',
                    'keywords': ['mac_address', 'macaddress', 'mac', 'name', 'mac1', 'mac_1', 'mac address 1']
                },
                'mac_address_2': {
                    'required': False,
                    'description': 'MAC Address 2',
                    'keywords': ['mac2', 'mac_2', 'mac address 2', 'mac_address_2', 'macaddress2']
                },
                'mac_address_3': {
                    'required': False,
                    'description': 'MAC Address 3',
                    'keywords': ['mac3', 'mac_3', 'mac address 3', 'mac_address_3', 'macaddress3']
                },
                'mac_address_4': {
                    'required': False,
                    'description': 'MAC Address 4',
                    'keywords': ['mac4', 'mac_4', 'mac address 4', 'mac_address_4', 'macaddress4']
                },
                'mac_address_5': {
                    'required': False,
                    'description': 'MAC Address 5',
                    'keywords': ['mac5', 'mac_5', 'mac address 5', 'mac_address_5', 'macaddress5']
                },
                'ip_address': {
                    'required': False,
                    'description': 'IP Address',
                    'keywords': ['ip_address', 'ipaddress', 'ip']
                },
                'dns_hostname': {
                    'required': False,
                    'description': 'DNS/Hostname',
                    'keywords': ['dns_hostname', 'dnshostname', 'dns', 'hostname', 'dns/hostname', 'host']
                },
                'zone': {
                    'required': False,
                    'description': 'Zone',
                    'keywords': ['zone']
                },
                'firmware_version': {
                    'required': False,
                    'description': 'Firmware Version',
                    'keywords': ['firmware_version', 'firmwareversion', 'firmware']
                },
                'model': {
                    'required': False,
                    'description': 'Model',
                    'keywords': ['model']
                },
                'country': {
                    'required': False,
                    'description': 'Country',
                    'keywords': ['country']
                },
                'office': {
                    'required': False,
                    'description': 'Office',
                    'keywords': ['office']
                },
                'desk_location': {
                    'required': False,
                    'description': 'Desk Location',
                    'keywords': ['desk_location', 'desklocation', 'desk']
                }
            },
            'ceased_private_wire': {
                'record_no': {
                    'required': False,
                    'description': 'Record number (unique identifier)',
                    'keywords': ['record_no', 'record', 'recordno', 'id']
                },
                'original_record_no': {
                    'required': False,
                    'description': 'Original record number before cease',
                    'keywords': ['original_record_no', 'originalrecordno', 'original']
                },
                'aor_number': {
                    'required': False,
                    'description': 'AOR Number',
                    'keywords': ['aor_number', 'aornumber', 'aor']
                },
                'port_number': {
                    'required': False,
                    'description': 'Port Number',
                    'keywords': ['port_number', 'portnumber', 'port']
                },
                'channel_number': {
                    'required': False,
                    'description': 'Channel Number',
                    'keywords': ['channel_number', 'channelnumber', 'channel']
                },
                'location': {
                    'required': False,
                    'description': 'Physical location',
                    'keywords': ['location']
                },
                'dc_locale': {
                    'required': False,
                    'description': 'DC Locale',
                    'keywords': ['dc_locale', 'dclocale', 'dc']
                },
                'vega_port': {
                    'required': False,
                    'description': 'Vega Port',
                    'keywords': ['vega_port', 'vegaport', 'vega', 'port']
                },
                'channel': {
                    'required': False,
                    'description': 'Channel',
                    'keywords': ['channel']
                },
                'bearer_no': {
                    'required': False,
                    'description': 'Bearer Number',
                    'keywords': ['bearer_no', 'bearerno', 'bearer']
                },
                'circuit_no': {
                    'required': False,
                    'description': 'Circuit Number',
                    'keywords': ['circuit_no', 'circuitno', 'circuit']
                },
                'back_up_bearer': {
                    'required': False,
                    'description': 'Backup Bearer',
                    'keywords': ['back_up_bearer', 'backup_bearer', 'backupbearer']
                },
                'cluster_name': {
                    'required': False,
                    'description': 'Cluster Name',
                    'keywords': ['cluster_name', 'clustername', 'cluster']
                },
                'tpo_name': {
                    'required': False,
                    'description': 'TPO Name',
                    'keywords': ['tpo_name', 'tponame', 'tpo']
                },
                'vega_hostname': {
                    'required': False,
                    'description': 'Vega Hostname',
                    'keywords': ['vega_hostname', 'vegahostname', 'hostname']
                },
                'back_up_vega_gw': {
                    'required': False,
                    'description': 'Backup Vega Gateway',
                    'keywords': ['back_up_vega_gw', 'backup_vega_gw', 'backupvegagw']
                },
                'vendor': {
                    'required': False,
                    'description': 'Vendor',
                    'keywords': ['vendor']
                },
                'pw_type': {
                    'required': False,
                    'description': 'Private Wire Type',
                    'keywords': ['pw_type', 'pwtype', 'pw', 'type']
                },
                'btt_slot': {
                    'required': False,
                    'description': 'BTT Slot',
                    'keywords': ['btt_slot', 'bttslot', 'btt']
                },
                'aor': {
                    'required': False,
                    'description': 'AOR',
                    'keywords': ['aor']
                },
                'a_or_b': {
                    'required': False,
                    'description': 'A or B designation',
                    'keywords': ['a_or_b', 'aorb', 'a or b']
                },
                'dedicated_country': {
                    'required': False,
                    'description': 'Dedicated Country',
                    'keywords': ['dedicated_country', 'dedicatedcountry', 'country']
                },
                'hsbc_main_user': {
                    'required': False,
                    'description': 'HSBC Main User',
                    'keywords': ['hsbc_main_user', 'hsbcmainuser', 'mainuser', 'user']
                },
                'employee_id': {
                    'required': False,
                    'description': 'Employee ID',
                    'keywords': ['employee_id', 'employeeid', 'empid']
                },
                'private_public': {
                    'required': False,
                    'description': 'Private or Public',
                    'keywords': ['private_public', 'privatepublic', 'private / public']
                },
                'line_label': {
                    'required': False,
                    'description': 'Line Label',
                    'keywords': ['line_label', 'linelabel', 'label']
                },
                'company_name': {
                    'required': False,
                    'description': 'Company Name',
                    'keywords': ['company_name', 'companyname', 'company']
                },
                'company_contact': {
                    'required': False,
                    'description': 'Company Contact',
                    'keywords': ['company_contact', 'companycontact', 'contact']
                },
                'company_email': {
                    'required': False,
                    'description': 'Company Email',
                    'keywords': ['company_email', 'companyemail', 'email']
                },
                'vr_yn': {
                    'required': False,
                    'description': 'VR Yes/No',
                    'keywords': ['vr_yn', 'vryn', 'vr', 'vr y / n']
                },
                'snow_ref': {
                    'required': False,
                    'description': 'SNOW Reference',
                    'keywords': ['snow_ref', 'snowref', 'snow']
                },
                'cease_date': {
                    'required': False,
                    'description': 'Cease Date',
                    'keywords': ['cease_date', 'ceasedate', 'cease', 'date']
                },
                'ceased_by': {
                    'required': False,
                    'description': 'Ceased By (username)',
                    'keywords': ['ceased_by', 'ceasedby', 'ceased', 'by']
                },
                'cease_reason': {
                    'required': False,
                    'description': 'Cease Reason',
                    'keywords': ['cease_reason', 'ceasereason', 'reason']
                }
            },
            'changes': {
                'cr_number': {
                    'required': False,
                    'description': 'Change Request Number',
                    'keywords': ['cr_number', 'crnumber', 'cr', 'change number', 'change_number']
                },
                'region': {
                    'required': False,
                    'description': 'Region',
                    'keywords': ['region']
                },
                'status': {
                    'required': False,
                    'description': 'Status (New, Cancelled, Assess)',
                    'keywords': ['status']
                },
                'title': {
                    'required': False,
                    'description': 'Change Title',
                    'keywords': ['title', 'change title', 'change_title']
                },
                'change_category': {
                    'required': False,
                    'description': 'Change Category',
                    'keywords': ['change_category', 'changecategory', 'category']
                },
                'technology': {
                    'required': False,
                    'description': 'Technology',
                    'keywords': ['technology', 'tech']
                },
                'change_risk_level': {
                    'required': False,
                    'description': 'Change Risk Level',
                    'keywords': ['change_risk_level', 'changerisklevel', 'risk', 'risk level']
                },
                'raised_by': {
                    'required': False,
                    'description': 'Raised By',
                    'keywords': ['raised_by', 'raisedby', 'raised', 'raised by']
                },
                'tech_lead': {
                    'required': False,
                    'description': 'Tech Lead',
                    'keywords': ['tech_lead', 'techlead', 'tech lead']
                },
                'start_date': {
                    'required': False,
                    'description': 'Start Date',
                    'keywords': ['start_date', 'startdate', 'start date']
                },
                'cab_date': {
                    'required': False,
                    'description': 'CAB Date',
                    'keywords': ['cab_date', 'cabdate', 'cab date', 'cab']
                },
                'ice_sent': {
                    'required': False,
                    'description': 'ICE Sent (Yes/No)',
                    'keywords': ['ice_sent', 'icesent', 'ice sent']
                },
                'ice_approved': {
                    'required': False,
                    'description': 'ICE Approved (Yes/No/N/A)',
                    'keywords': ['ice_approved', 'iceapproved', 'ice approved']
                },
                'regional_approval_status': {
                    'required': False,
                    'description': 'Regional Approval Status',
                    'keywords': ['regional_approval_status', 'regionalapprovalstatus', 'regional approval']
                },
                'regional_approver_name': {
                    'required': False,
                    'description': 'Regional Approver Name',
                    'keywords': ['regional_approver_name', 'regionalapprovername', 'regional approver']
                },
                'approved_status': {
                    'required': False,
                    'description': 'Approved Status',
                    'keywords': ['approved_status', 'approvedstatus', 'approved']
                },
                'approved_by': {
                    'required': False,
                    'description': 'Approved By',
                    'keywords': ['approved_by', 'approvedby', 'approved by']
                },
                'snow_link': {
                    'required': False,
                    'description': 'SNOW Link',
                    'keywords': ['snow_link', 'snowlink', 'snow', 'snow link']
                },
                'bau_project': {
                    'required': False,
                    'description': 'BAU/Project',
                    'keywords': ['bau_project', 'bauproject', 'bau', 'project']
                },
                'regular_change': {
                    'required': False,
                    'description': 'Regular Change (Yes/No)',
                    'keywords': ['regular_change', 'regularchange', 'regular change']
                },
                'risk_mitigation': {
                    'required': False,
                    'description': 'Risk Mitigation',
                    'keywords': ['risk_mitigation', 'riskmitigation', 'risk mitigation']
                },
                'comments': {
                    'required': False,
                    'description': 'Comments',
                    'keywords': ['comments', 'comment']
                },
                'coo_update': {
                    'required': False,
                    'description': 'COO Update',
                    'keywords': ['coo_update', 'cooupdate', 'coo update']
                },
                'global_service_approval': {
                    'required': False,
                    'description': 'Global Service Approval',
                    'keywords': ['global_service_approval', 'globalserviceapproval', 'global service approval', 'gsa']
                }
            },
            'incidents': {
                'incident_number': {
                    'required': False,
                    'description': 'Incident Number',
                    'keywords': ['incident_number', 'incidentnumber', 'incident', 'incident number']
                },
                'verint_number': {
                    'required': False,
                    'description': 'Verint Ref',
                    'keywords': ['verint_number', 'verintnumber', 'verint', 'verint ref', 'verint_ref']
                },
                'small_title': {
                    'required': False,
                    'description': 'Small Title (100 chars)',
                    'keywords': ['small_title', 'smalltitle', 'small title', 'short title', 'title_100']
                },
                'incident_summary': {
                    'required': False,
                    'description': 'Incident Summary',
                    'keywords': ['incident_summary', 'incidentsummary', 'incident summary', 'summary', 'title']
                },
                'zendesk_number': {
                    'required': False,
                    'description': 'Zendesk Number',
                    'keywords': ['zendesk_number', 'zendesknumber', 'zendesk', 'zendesk number']
                },
                'technology': {
                    'required': False,
                    'description': 'Technology',
                    'keywords': ['technology', 'tech']
                },
                'location': {
                    'required': False,
                    'description': 'Location',
                    'keywords': ['location']
                },
                'severity': {
                    'required': False,
                    'description': 'Severity',
                    'keywords': ['severity']
                },
                'overview': {
                    'required': False,
                    'description': 'Overview',
                    'keywords': ['overview']
                },
                'rca_link': {
                    'required': False,
                    'description': 'RCA Link',
                    'keywords': ['rca_link', 'rcalink', 'rca', 'rca link']
                },
                'incident_date': {
                    'required': False,
                    'description': 'Incident Date',
                    'keywords': ['incident_date', 'incidentdate', 'incident date', 'date']
                }
            }
        }
    
    def analyze_csv_headers(self, csv_headers: List[str], import_type: str) -> Dict[str, Optional[str]]:
        """
        Analyze CSV headers and suggest mappings based on keywords
        """
        suggestions = {}
        field_defs = self.field_definitions.get(import_type, {})
        
        # Initialize all fields as unmapped
        for field_name in field_defs.keys():
            suggestions[field_name] = None
        
        # Try to match headers to fields
        for csv_header in csv_headers:
            header_lower = csv_header.lower().replace(' ', '_').replace('-', '_')
            
            best_match = None
            best_score = 0
            
            for field_name, field_def in field_defs.items():
                if suggestions[field_name] is not None:
                    continue  # Already mapped
                
                # Check for exact keyword matches
                for keyword in field_def['keywords']:
                    if keyword.lower() in header_lower:
                        score = len(keyword) / len(header_lower)
                        if score > best_score:
                            best_score = score
                            best_match = field_name
            
            if best_match and best_score > 0.3:  # Minimum threshold
                suggestions[best_match] = csv_header
        
        return suggestions
    
    def get_field_definitions(self, import_type: str) -> Dict:
        """Get field definitions for a specific import type"""
        return self.field_definitions.get(import_type, {})
    
    def validate_mappings(self, mappings: Dict[str, str], import_type: str) -> Tuple[bool, List[str]]:
        """
        Validate that required fields are mapped
        Returns: (is_valid, list_of_errors)
        """
        errors = []
        field_defs = self.field_definitions.get(import_type, {})
        
        for field_name, field_def in field_defs.items():
            if field_def['required'] and (field_name not in mappings or not mappings[field_name]):
                errors.append(f"Required field '{field_name}' must be mapped")
        
        return len(errors) == 0, errors