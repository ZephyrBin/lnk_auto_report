import struct
import os
from datetime import datetime
import win32com.client
import hashlib
import requests
import matplotlib.pyplot as plt
import numpy as np
import io
import base64
from jinja2 import Template
from generate_report import generate_report

class LNKAnalyzer:
    def __init__(self, lnk_path, vt_api_key=None):
        self.lnk_path = lnk_path
        self.vt_api_key = vt_api_key
        self.risk_score = 0
        self.findings = []
        self.suspicious = []
        self.malicious = []
        self.structure_info = {}
        
        # Known Extra Data Block signatures
        self.KNOWN_BLOCKS = {
            0xA0000001: ('ConsoleDataBlock', 0x0C),
            0xA0000002: ('ConsoleFEDataBlock', 0x0C),
            0xA0000003: ('DarwinDataBlock', 0x314),
            0xA0000004: ('EnvironmentVariableDataBlock', 0x314),
            0xA0000005: ('IconEnvironmentDataBlock', 0x314),
            0xA0000006: ('KnownFolderDataBlock', 0x1C),
            0xA0000007: ('PropertyStoreDataBlock', None),
            0xA0000008: ('ShimDataBlock', None),
            0xA0000009: ('SpecialFolderDataBlock', 0x10),
            0xA000000A: ('TrackerDataBlock', 0x58),
            0xA000000B: ('VistaAndAboveIDListDataBlock', None),
        }

    def read_lnk_header(self, data):
        header = {
            'HeaderSize': struct.unpack('<I', data[0:4])[0],
            'LinkCLSID': data[4:20].hex(),
            'LinkFlags': struct.unpack('<I', data[20:24])[0],
            'FileAttributes': struct.unpack('<I', data[24:28])[0],
            'CreationTime': self._filetime_to_datetime(struct.unpack('<Q', data[28:36])[0]),
            'AccessTime': self._filetime_to_datetime(struct.unpack('<Q', data[36:44])[0]),
            'WriteTime': self._filetime_to_datetime(struct.unpack('<Q', data[44:52])[0]),
            'FileSize': struct.unpack('<I', data[52:56])[0],
            'IconIndex': struct.unpack('<I', data[56:60])[0],
            'ShowCommand': struct.unpack('<I', data[60:64])[0],
            'HotKey': struct.unpack('<H', data[64:66])[0],
            'Reserved1': struct.unpack('<H', data[66:68])[0],
            'Reserved2': struct.unpack('<I', data[68:72])[0],
            'Reserved3': struct.unpack('<I', data[72:76])[0],
        }
        return header

    def analyze_flags(self, flags):
        flag_descriptions = {
            'HasLinkTargetIDList': (flags & 0x1, "Contains Link Target ID List"),
            'HasLinkInfo': (flags & 0x2, "Contains Link Info Structure"),
            'HasName': (flags & 0x4, "Contains String Data: NAME"),
            'HasRelativePath': (flags & 0x8, "Contains String Data: RELATIVE_PATH"),
            'HasWorkingDir': (flags & 0x10, "Contains String Data: WORKING_DIR"),
            'HasArguments': (flags & 0x20, "Contains String Data: COMMAND_LINE_ARGUMENTS"),
            'HasIconLocation': (flags & 0x40, "Contains String Data: ICON_LOCATION"),
            'IsUnicode': (flags & 0x80, "String data is Unicode encoded"),
            'ForceNoLinkInfo': (flags & 0x100, "Shell Link should not use Link Info"),
            'HasExpString': (flags & 0x200, "Contains EnvironmentVariableDataBlock"),
            'RunInSeparateProcess': (flags & 0x400, "Target should run in separate process"),
            'HasDarwinID': (flags & 0x1000, "Contains DarwinDataBlock"),
            'RunAsUser': (flags & 0x2000, "Target should run as user"),
            'HasExpIcon': (flags & 0x4000, "Contains IconEnvironmentDataBlock"),
            'NoPidlAlias': (flags & 0x8000, "Shell Link is saved without a PIDL"),
            'RunWithShimLayer': (flags & 0x20000, "Contains ShimDataBlock"),
            'ForceNoLinkTrack': (flags & 0x40000, "Should not be tracked"),
            'EnableTargetMetadata': (flags & 0x80000, "Shell Link can collect target properties"),
            'DisableLinkPathTracking': (flags & 0x100000, "Link path should not be tracked"),
            'DisableKnownFolderTracking': (flags & 0x200000, "Known folder should not be tracked"),
            'DisableKnownFolderAlias': (flags & 0x400000, "Should not use known folder alias"),
            'AllowLinkToLink': (flags & 0x800000, "Can link to another Shell Link"),
            'UnaliasOnSave': (flags & 0x1000000, "Should be unaliased when saved"),
            'PreferEnvironmentPath': (flags & 0x2000000, "Prefer system env path"),
            'KeepLocalIDListForUNCTarget': (flags & 0x4000000, "Keep local ID list for UNC target"),
        }
        return {name: (value, desc) for name, (value, desc) in flag_descriptions.items()}

    def analyze_extra_blocks(self, data, offset):
        blocks = []
        current_offset = offset
        block_count = 0
        env_block_data = None
        icon_env_block_data = None

        while current_offset < len(data):
            if current_offset + 8 > len(data):
                break

            block_size = struct.unpack('<I', data[current_offset:current_offset+4])[0]
            if block_size == 0:
                break

            signature = struct.unpack('<I', data[current_offset+4:current_offset+8])[0]
            
            block_info = {
                'offset': hex(current_offset),
                'size': block_size,
                'signature': hex(signature),
                'name': self.KNOWN_BLOCKS.get(signature, ('Unknown', None))[0],
                'expected_size': self.KNOWN_BLOCKS.get(signature, ('Unknown', None))[1],
                'data': self.parse_environment_block(data, current_offset, block_size)
            }
            
            # Analyze EnvironmentVariableDataBlock
            if signature == 0xA0000004:  # EnvironmentVariableDataBlock
                block_info['data'] = self.parse_environment_block(data, current_offset, block_size)
                env_block_data = block_info['data']
            
            # Analyze IconEnvironmentDataBlock
            elif signature == 0xA0000005:  # IconEnvironmentDataBlock
                block_info['data'] = self.parse_environment_block(data, current_offset, block_size)
                icon_env_block_data = block_info['data']

            # Check suspicious patterns
            if signature not in self.KNOWN_BLOCKS:
                self.suspicious.append(f"Unknown Extra Data Block signature: {hex(signature)}")
                self.risk_score += 3
            elif (self.KNOWN_BLOCKS[signature][1] and 
                  block_size != self.KNOWN_BLOCKS[signature][1]):
                self.suspicious.append(
                    f"Invalid block size for {block_info['name']}: "
                    f"Expected {self.KNOWN_BLOCKS[signature][1]}, Got {block_size}")
                self.risk_score += 0.1

            blocks.append(block_info)
            current_offset += block_size
            block_count += 1

        # Compare Icon
        if env_block_data and icon_env_block_data:
            env_target = env_block_data.get('TargetUnicode', '').lower()
            icon_target = icon_env_block_data.get('TargetUnicode', '').lower()
            if env_target and icon_target and env_target != icon_target:
                self.suspicious.append(
                    f"Icon mismatch detected:\n"
                    f"Environment Target: {env_target}\n"
                    f"Icon Target: {icon_target}"
                )
                self.risk_score += 0.5

        # Compare Shell Link and IconLocation
        if icon_env_block_data and hasattr(self, 'structure_info'):
            shell_icon = self.structure_info.get('IconLocation', '').lower()
            icon_block = icon_env_block_data.get('TargetUnicode', '').lower()
            if shell_icon and icon_block and shell_icon != icon_block:
                self.suspicious.append(
                    f"Shell Link and IconEnvironmentDataBlock icon mismatch:\n"
                    f"Shell Link Icon: {shell_icon}\n"
                    f"Icon Block: {icon_block}"
                )
                self.risk_score += 0.5

        if block_count > 11:
            self.suspicious.append(
                f"Suspicious number of Extra Data Blocks: {block_count}")
            self.risk_score += 3

        return blocks

    def parse_environment_block(self, data, offset, block_size):
        try:
        # Start after block header(8bytes)
            current_offset = offset + 8
            target_ansi = data[current_offset:current_offset+260].split(b'\x00')[0].decode('ascii', errors='ignore')
            current_offset += 260
            target_unicode = data[current_offset:current_offset+520].split(b'\x00\x00')[0].decode('utf-16le', errors='ignore')
        
            return {
                'TargetAnsi': target_ansi,
                'TargetUnicode': target_unicode
            }
        except Exception as e:
            return {
                'error': f"Failed to parse EnvironmentVariableDataBlock: {str(e)}"
            }

    def check_virustotal(self, file_hash):
        if not self.vt_api_key:
            return {"error": "No VirusTotal API key provided"}

        url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {
            'apikey': self.vt_api_key,
            'resource': file_hash
        }

        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                result = response.json()
                if result.get('response_code') == 1:
                    if result.get('positives', 0) > 0:
                        self.risk_score += min(5, result.get('positives') / 2)
                    return {
                        'found': True,
                        'positives': result.get('positives', 0),
                        'total': result.get('total', 0),
                        'scan_date': result.get('scan_date', ''),
                        'permalink': result.get('permalink', '')
                    }
                return {'found': False, 'message': 'File not found in VirusTotal'}
            return {'error': f'API request failed with status code {response.status_code}'}
        except Exception as e:
            return {'error': f'API request failed: {str(e)}'}

    def _filetime_to_datetime(self, filetime):
        if filetime == 0:
            return "Not set"
        return datetime.fromtimestamp((filetime - 116444736000000000) // 10000000)

    def generate_risk_gauge(self):
        plt.figure(figsize=(10, 2))
        plt.axis('off')
        
        # Create gradient background
        gradient = np.linspace(0, 1, 100)
        plt.imshow([gradient], extent=[0, 10, 0, 1], aspect='auto', cmap='RdYlGn_r')
        
        # Add pointer
        plt.plot([self.risk_score, self.risk_score], [0, 1], 'k-', linewidth=2)
        
        # Add score text
        plt.text(self.risk_score, 1.2, f'Risk Score: {self.risk_score}/10', 
                ha='center', va='bottom')
        
        # Save to base64
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight', transparent=True)
        plt.close()
        return base64.b64encode(buf.getvalue()).decode('utf-8')

    def analyze(self):
        try:
            shell = win32com.client.Dispatch("WScript.Shell")
            shell_link = shell.CreateShortCut(self.lnk_path)

            with open(self.lnk_path, 'rb') as f:
                data = f.read()
                
            # Calculate file hashes
            self.file_hashes = {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest()
            }

            # Check VirusTotal
            self.vt_results = self.check_virustotal(self.file_hashes['sha256'])

            # Analyze header
            header = self.read_lnk_header(data)
            flags = self.analyze_flags(header['LinkFlags'])

            # Store structure information
            self.structure_info = {
                'Header': header,
                'Flags': flags,
                'TargetPath': shell_link.TargetPath,
                'Arguments': shell_link.Arguments,
                'WorkingDirectory': shell_link.WorkingDirectory,
                'IconLocation': shell_link.IconLocation,
                'WindowStyle': header['ShowCommand'],
                'FileSize': os.path.getsize(self.lnk_path),
                'ExtraBlocks': []
            }

            # Analyze suspicious patterns
            if header['ShowCommand'] == 7:
                self.suspicious.append("Suspicious ShowCommand value (7) - Minimized execution")
                self.risk_score += 3

            if shell_link.Arguments:
                suspicious_commands = [
                    'powershell', 'cmd.exe', 'rundll32', 'regsvr32', 'mshta',
                    'certutil', 'bitsadmin', 'wscript', 'cscript', 'msiexec'
                ]
                for cmd in suspicious_commands:
                    if cmd.lower() in shell_link.Arguments.lower():
                        self.malicious.append(f"Malicious command found in arguments: {cmd}")
                        self.risk_score += 4

            # Analyze Extra Data Blocks
            offset = 76  # Start after header
            if flags['HasLinkTargetIDList'][0]:
                idlist_size = struct.unpack('<H', data[offset:offset+2])[0]
                offset += 2 + idlist_size

            if flags['HasLinkInfo'][0]:
                linkinfo_size = struct.unpack('<I', data[offset:offset+4])[0]
                offset += linkinfo_size

            # Skip String Data
            for flag in ['HasName', 'HasRelativePath', 'HasWorkingDir', 
                        'HasArguments', 'HasIconLocation']:
                if flags[flag][0]:
                    if flags['IsUnicode'][0]:
                        str_size = struct.unpack('<H', data[offset:offset+2])[0] * 2
                    else:
                        str_size = struct.unpack('<H', data[offset:offset+2])[0]
                    offset += 2 + str_size

            # Analyze Extra Data Blocks
            self.structure_info['ExtraBlocks'] = self.analyze_extra_blocks(data, offset)

            # Generate report
            generate_report(self)

        except Exception as e:
            print(f"Error analyzing LNK file: {str(e)}")