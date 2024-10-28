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
import re

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
            0xA0000002: ('ConsoleDataBlock', 0x0C),
            0xA0000004: ('ConsoleFEDataBlock', 0x0C),
            0xA0000006: ('DarwinDataBlock', 0x314),
            0xA0000001: ('EnvironmentVariableDataBlock', 0x314),
            0xA0000007: ('IconEnvironmentDataBlock', 0x314),
            0xA000000B: ('KnownFolderDataBlock', 0x1C),
            0xA0000009: ('PropertyStoreDataBlock', None),
            0xA0000008: ('ShimDataBlock', None),
            0xA0000005: ('SpecialFolderDataBlock', 0x10),
            0xA0000003: ('TrackerDataBlock', 0x58),
            0xA000000C: ('VistaAndAboveIDListDataBlock', None),
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

    def parse_string_data(self, data, offset, is_unicode):
        try:
            string_size = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
        
            if is_unicode:
                string_data = data[offset:offset+string_size*2].decode('utf-16le', errors='ignore')
                return string_data, 2 + (string_size * 2)
            else:
                string_data = data[offset:offset+string_size].decode('ascii', errors='ignore')
                return string_data, 2 + string_size
        except Exception as e:
            return f"Error parsing string: {str(e)}", 2

    def analyze_string_data(self, data, offset, flags):
        string_data = {}
        current_offset = offset
        is_unicode = flags['IsUnicode'][0]

        string_order = [
            ('HasName', 'NAME'),
            ('HasRelativePath', 'RELATIVE_PATH'),
            ('HasWorkingDir', 'WORKING_DIR'),
            ('HasArguments', 'COMMAND_LINE_ARGUMENTS'),
            ('HasIconLocation', 'ICON_LOCATION')
        ]

        for flag_name, string_type in string_order:
            if flags[flag_name][0]:
                string_size = struct.unpack('<H', data[current_offset:current_offset+2])[0]
                size_hex = data[current_offset:current_offset+2].hex()
                
                string_size = struct.unpack('<H', data[current_offset:current_offset+2])[0]
                size_hex = data[current_offset:current_offset+2].hex()

                if is_unicode:
                    string_data_size = string_size * 2
                    string_value = data[current_offset+2:current_offset+2+string_data_size].decode('utf-16le', errors='ignore')
                else:
                    string_data_size = string_size
                    string_value = data[current_offset+2:current_offset+2+string_data_size].decode('ascii', errors='ignore')

                string_data[string_type] = {
                    'value': string_value,
                    'offset': hex(current_offset),
                    'size': string_data_size,
                    'size_hex': f"Size: {size_hex} ({string_size})",
                    'raw_hex': data[current_offset+2:current_offset+2+string_data_size].hex(),
                    'total_size': 2 + string_data_size
                }

                current_offset += 2 + string_data_size

                # 의심스러운 문자열 검사
                if string_type == 'COMMAND_LINE_ARGUMENTS':
                    self.check_suspicious_commands(string_value)

        return string_data, current_offset

    def check_suspicious_commands(self, command_string):
        if not command_string:
            return

        suspicious_patterns = [
            (r'powershell.*-enc.*', 'Encoded PowerShell command'),
            (r'powershell.*', 'PowerShell command'),
            (r'cmd.*/c.*', 'Command prompt execution'),
            (r'rundll32.*,', 'RunDLL32 usage'),
            (r'%.*%.*%', 'Multiple environment variables'),
            (r'\\\\.*\\.*\$', 'Hidden share access'),
            (r'certutil.*-decode', 'Certificate utility decode'),
            (r'mshta.*http', 'MSHTA with URL'),
        ]

        for pattern, description in suspicious_patterns:
            if re.search(pattern, command_string, re.IGNORECASE):
                self.suspicious.append(f"Suspicious command pattern: {description}")
                self.risk_score += 3

    def parse_extra_block_data(self, signature, data):
        try:
            if signature == 0xA0000002:  # ConsoleDataBlock
                return {
                    'type': 'ConsoleDataBlock',
                    'fill_attributes': struct.unpack('<H', data[0:2])[0],
                    'popup_fill_attributes': struct.unpack('<H', data[2:4])[0],
                    'screen_buffer_size_x': struct.unpack('<H', data[4:6])[0],
                    'screen_buffer_size_y': struct.unpack('<H', data[6:8])[0],
                    'window_size_x': struct.unpack('<H', data[8:10])[0],
                    'window_size_y': struct.unpack('<H', data[10:12])[0]
                }
            
            elif signature == 0xA0000004:  # ConsoleFEDataBlock
                return {
                    'type': 'ConsoleFEDataBlock',
                    'code_page': struct.unpack('<I', data[0:4])[0]
                }
                
            elif signature == 0xA0000006:  # DarwinDataBlock
                app_name = data[0:260].split(b'\x00')[0].decode('ascii', errors='ignore')
                return {
                    'type': 'DarwinDataBlock',
                    'darwin_data_ansi': app_name
                }
                
            elif signature == 0xA0000001:  # EnvironmentVariableDataBlock
                target_ansi = data[0:260].split(b'\x00')[0].decode('ascii', errors='ignore')
                target_unicode = data[260:520].split(b'\x00\x00')[0].decode('utf-16le', errors='ignore')
                return {
                    'type': 'EnvironmentVariableDataBlock',
                    'target_ansi': target_ansi,
                    'target_unicode': target_unicode
                }
                
            elif signature == 0xA0000007:  # IconEnvironmentDataBlock
                target_ansi = data[0:260].split(b'\x00')[0].decode('ascii', errors='ignore')
                target_unicode = data[260:520].split(b'\x00\x00')[0].decode('utf-16le', errors='ignore')
                return {
                    'type': 'IconEnvironmentDataBlock',
                    'target_ansi': target_ansi,
                    'target_unicode': target_unicode
                }
                
            elif signature == 0xA000000B:  # KnownFolderDataBlock
                return {
                    'type': 'KnownFolderDataBlock',
                    'known_folder_id': data[0:16].hex(),
                    'offset': struct.unpack('<I', data[16:20])[0]
                }
                
            elif signature == 0xA0000008:  # ShimDataBlock
                return {
                    'type': 'ShimDataBlock',
                    'layer_name': data.split(b'\x00\x00')[0].decode('utf-16le', errors='ignore')
                }
                
            elif signature == 0xA0000005:  # SpecialFolderDataBlock
                return {
                    'type': 'SpecialFolderDataBlock',
                    'special_folder_id': struct.unpack('<I', data[0:4])[0],
                    'offset': struct.unpack('<I', data[4:8])[0]
                }
                
            elif signature == 0xA0000003:  # TrackerDataBlock
                return {
                    'type': 'TrackerDataBlock',
                    'length': struct.unpack('<I', data[0:4])[0],
                    'version': struct.unpack('<I', data[4:8])[0],
                    'machine_id': data[8:16].hex(),
                    'droid_volume_id': data[16:32].hex(),
                    'droid_file_id': data[32:48].hex(),
                    'birth_droid_volume_id': data[48:64].hex(),
                    'birth_droid_file_id': data[64:80].hex(),
                }
                
            elif signature == 0xA000000C:  # VistaAndAboveIDListDataBlock
                return {
                    'type': 'VistaAndAboveIDListDataBlock',
                    'data': data.hex()
                }
            
            elif signature == 0xA0000009:
                return {
                    'type': 'PropertyStoreDataBlock',
                    'data': data.hex()
                }
                
            else:
                return {
                    'type': 'Unknown',
                    'note': f'Unknown signature: {hex(signature)}'
                }
                
        except Exception as e:
            return {
                'type': 'Error',
                'error': f'Failed to parse block data: {str(e)}'
            }

    def analyze_extra_blocks(self, data, offset):
        blocks = []
        current_offset = offset

        while current_offset < len(data):
            if current_offset + 8 > len(data):
                break

            block_size_bytes = data[current_offset:current_offset+4]
            block_size = struct.unpack('<I', block_size_bytes)[0]
            if block_size == 0:
                break

            signature_bytes = data[current_offset+4:current_offset+8]
            signature = struct.unpack('<I', signature_bytes)[0]
            
            block_info = {
                'offset': hex(current_offset),
                'size': block_size,
                'size_hex': f"Size: {block_size_bytes.hex()} ({block_size})",
                'signature': hex(signature), 
                'signature_hex': signature_bytes.hex(),
                'name': self.KNOWN_BLOCKS.get(signature, ('Unknown', None))[0],
                'expected_size': self.KNOWN_BLOCKS.get(signature, ('Unknown', None))[1],
                'data_hex': (data[current_offset+8:current_offset+block_size].hex())[0:1000],
                'parsed_data': self.parse_extra_block_data(signature, data[current_offset+8:current_offset+block_size])
            }

            # Check suspicious patterns
            if signature not in self.KNOWN_BLOCKS:
                self.suspicious.append(f"Unknown Extra Data Block signature: {hex(signature)}")
                self.risk_score += 4
            elif (self.KNOWN_BLOCKS[signature][1] and 
                block_size != self.KNOWN_BLOCKS[signature][1]):
                self.suspicious.append(
                    f"Invalid block size for {block_info['name']}: "
                    f"Expected {self.KNOWN_BLOCKS[signature][1]}, Got {block_size}")
                self.risk_score += 0.2

            blocks.append(block_info)
            current_offset += block_size

        return blocks


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

            # 기본 위험도 검사
            if header['ShowCommand'] == 7:
                self.suspicious.append("Suspicious ShowCommand value (7) - Minimized execution")
                self.risk_score += 4

            # 초기 구조 정보 설정
            self.structure_info = {
                'Header': {
                    'Size': header['HeaderSize'],
                    'Data': header,
                    'Description': 'Shell Link Header',
                    'Flags': flags
                },
                'LinkTargetIDList': {
                    'Size': 0,
                    'Hex': None,
                    'Data': None,
                    'Description': 'Contains ID list of target'
                },
                'LinkInfo': {
                    'Size': 0,
                    'Hex': None,
                    'Data': None,
                    'Description': 'Contains information about linked file'
                },
                'StringData': {
                    'Size': 0,
                    'Data': None,
                    'Description': 'Contains various string properties'
                },
                'ExtraData': {
                    'Size': 0,
                    'Data': [],
                    'Description': 'Contains additional data blocks'
                },
                'ShellLinkInfo': {
                    'TargetPath': shell_link.TargetPath,
                    'Arguments': shell_link.Arguments,
                    'WorkingDirectory': shell_link.WorkingDirectory,
                    'IconLocation': shell_link.IconLocation,
                    'WindowStyle': header['ShowCommand'],
                    'FileSize': os.path.getsize(self.lnk_path),
                }
            }

            # 구조 분석 시작
            offset = 76  # 헤더 이후 시작

            # LinkTargetIDList 처리
            if flags['HasLinkTargetIDList'][0]:
                idlist_size = struct.unpack('<H', data[offset:offset+2])[0]
                self.structure_info['LinkTargetIDList']['Size'] = idlist_size + 2
                self.structure_info['LinkTargetIDList']['Data'] = data[offset:offset+idlist_size+2].hex()
                offset += 2 + idlist_size

            # LinkInfo 처리
            if flags['HasLinkInfo'][0]:
                linkinfo_size = struct.unpack('<I', data[offset:offset+4])[0]
                self.structure_info['LinkInfo']['Size'] = linkinfo_size
                self.structure_info['LinkInfo']['Data'] = data[offset:offset+linkinfo_size].hex()
                offset += linkinfo_size

            has_string_data = any([
                flags['HasName'][0],
                flags['HasRelativePath'][0],
                flags['HasWorkingDir'][0],
                flags['HasArguments'][0],
                flags['HasIconLocation'][0]
            ])

            # String Data 분석
            if has_string_data:
                string_data, new_offset = self.analyze_string_data(data, offset, flags)
                self.structure_info['StringData']['Data'] = string_data
                self.structure_info['StringData']['Size'] = new_offset - offset
                offset = new_offset
            # Extra Data Blocks 분석
            extra_blocks = self.analyze_extra_blocks(data, offset)
            self.structure_info['ExtraData']['Data'] = extra_blocks
            if extra_blocks:
                total_extra_size = sum(block['size'] for block in extra_blocks)
                self.structure_info['ExtraData']['Size'] = total_extra_size

            if (self.risk_score > 10):
                self.risk_score = 10

            # 보고서 생성
            generate_report(self)

        except Exception as e:
            print(f"Error analyzing LNK file: {str(e)}")