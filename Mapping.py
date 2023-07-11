import concurrent.futures
import hashlib
import io
import json
import multiprocessing
import os
import re
import socket
import tempfile
import time
import concurrent.futures
import chardet
import dpkt
import magic
import requests
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from collections import namedtuple


# Global variables
base_url = 'https://otx.alienvault.com/api/v1'
OTX_API_KEY = 'Alien_Vault_Key'
VT_API_KEY = "Virus_Total_Key"
MAX_LOOKUPS_PER_MINUTE = 4 
MAX_LOOKUPS_PER_DAY = 500
MAX_LOOKUPS_PER_MONTH = 15500
LOOKUP_COUNTER = 0
LOOKUP_RESET_TIME = 0

# Global variables for tracking suspicious and malicious indicators
suspicious_ips = set()
malicious_ips = set()
malicious_domains = set()
MaliciousFile = namedtuple("MaliciousFile", ["session_key", "virus_name", "virus_type", "virus_family"])
malicious_files = set()


def main():
    pcap_file_path = 'Your_PCAP_FIle'  # Path to the pcap file
    kml_file_path = 'KML_File_Name/Path'  # Path to the output KML file

    pcap_data = read_pcap_file(pcap_file_path)  # Read pcap file data
    extracted_files, temp_files = extract_files(pcap_data)  # Extract files from pcap data
    compute_file_hashes(extracted_files, temp_files)  # Compute hashes for extracted files
    kmldoc = generate_kml(pcap_data)  # Generate KML document from pcap data

    write_kml_file(kmldoc, kml_file_path)  # Write KML document to a file


def read_pcap_file(file_path):
    with open(file_path, 'rb') as f:
        pcap_data = f.read()  # Read pcap file data
    return pcap_data


def parse_pcap(packet_list):
    sessions = []
    for packet in packet_list:
        if packet.haslayer(Raw):
            if packet.haslayer(IP) and packet.haslayer(TCP):
                if not sessions:
                    packets = [packet]
                    session = {
                        'IP1': packet['IP'].src,
                        'IP2': packet['IP'].dst,
                        'PORT1': packet['TCP'].sport,
                        'PORT2': packet['TCP'].dport,
                        'PACKETS': packets,
                        'CONVO_SIZE': packet['IP'].len
                    }
                    sessions.append(session)
                else:
                    found = False
                    for session in sessions:
                        if (
                                packet['IP'].src == session['IP1']
                                and packet['IP'].dst == session['IP2']
                                and packet['TCP'].sport == session['PORT1']
                                and packet['TCP'].dport == session['PORT2']
                        ):
                            session['PACKETS'].append(packet)
                            session['CONVO_SIZE'] += packet['IP'].len
                            found = True
                    if not found:
                        packets = [packet]
                        session = {
                            'IP1': packet['IP'].src,
                            'IP2': packet['IP'].dst,
                            'PORT1': packet['TCP'].sport,
                            'PORT2': packet['TCP'].dport,
                            'PACKETS': packets,
                            'CONVO_SIZE': packet['IP'].len
                        }
                        sessions.append(session)
    return sessions


def extract_files(pcap_file):
    temp_pcap = tempfile.NamedTemporaryFile(delete=False)
    temp_pcap.write(pcap_file)
    temp_pcap.close()

    packets = rdpcap(temp_pcap.name)
    extracted_files = []
    count = 1
    temp_files = []  # Define an empty list to store temporary file paths

    sessions = parse_pcap(packets)  # Parse the pcap packets to get sessions

    for session in sessions:
        ip1_len = 0
        ip2_len = 0
        ip1_session = b''
        ip2_session = b''
        filenames = []

        for packet in session['PACKETS']:
            if packet['IP'].src == session['IP1']:
                ip1_len += packet['IP'].len
                try:
                    ip1_session += bytes(packet[Raw].load)
                    if 'TCP' in packet:
                        filenames.append(packet['TCP'].options[2][1])
                except:
                    continue
            elif packet['IP'].src == session['IP2']:
                ip2_len += packet['IP'].len
                try:
                    ip2_session += bytes(packet[Raw].load)
                    if 'TCP' in packet:
                        filenames.append(packet['TCP'].options[2][1])
                except:
                    continue

        if ip1_len > ip2_len:
            file_size = ip1_len
            if file_size > 0:
                with io.BytesIO() as file:
                    file.write(ip1_session)
                    file.seek(0)  # Reset the file position to the beginning for reading
                    temp_file = tempfile.NamedTemporaryFile(delete=False)
                    temp_file.write(ip1_session)
                    temp_file.close()
                    temp_files.append(temp_file.name)
                    extension = get_extension(ip1_session)
                    extracted_files.append({
                        'filename': temp_file.name,
                        'session_size': session['CONVO_SIZE'],
                        'file_data': file.read(),
                        'sha256_hash': None,
                        'extension': extension,
                        'session_key': '-'.join(
                            [session['IP1'], session['IP2'], str(session['PORT1']), str(session['PORT2'])])
                    })
                count += 1
        elif ip1_len < ip2_len:
            file_size = ip2_len
            if file_size > 0:
                with io.BytesIO() as file:
                    file.write(ip2_session)
                    file.seek(0)  # Reset the file position to the beginning for reading
                    temp_file = tempfile.NamedTemporaryFile(delete=False)
                    temp_file.write(ip2_session)
                    temp_file.close()
                    temp_files.append(temp_file.name)
                    extension = get_extension(ip2_session)
                    extracted_files.append({
                        'filename': temp_file.name,
                        'session_size': session['CONVO_SIZE'],
                        'file_data': file.read(),
                        'sha256_hash': None,
                        'extension': extension,
                        'session_key': '-'.join(
                            [session['IP1'], session['IP2'], str(session['PORT1']), str(session['PORT2'])])
                    })
                count += 1

    os.remove(temp_pcap.name)

    return extracted_files, temp_files


def compute_file_hashes(extracted_files, temp_files):
    for i, file in enumerate(extracted_files):
        temp_file_path = temp_files[i]  # Get the corresponding temp file path
        try:
            with open(temp_file_path, 'rb') as file_content:
                sha256_hash = hashlib.sha256(file_content.read()).hexdigest()
            session_key = file['session_key']
            check_file_hashes(session_key, sha256_hash)
        except FileNotFoundError:
            print(f"File not found: {temp_file_path}")
        finally:
            # Remove the temporary file if it exists
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)


def get_extension(header):
    extension = magic.from_buffer(header, mime=False)
    if extension is None:
        extension = 'unknown'
    return extension


def generate_kml_for_ips(dst_coordinates, src_coordinates, dst_ip, suspicious=False, malicious=False, url=None,
                         virus_type=None, virus_name=None, virus_family=None):
    kml = '<Placemark>\n'
    kml += f'<name>{dst_ip}</name>\n'

    if malicious:
        kml += '<styleUrl>#redLine</styleUrl>\n'  # Red line style for malicious traffic
        kml += '<description>\n'

        if virus_type and virus_name and virus_family:
            kml += f'Malicious Virus Detected.\n'
            kml += f'{virus_name}.\n'
            kml += f'{virus_type}.\n'
            kml += f'{virus_family}.\n'
        elif url:
            kml += 'Malicious {url} and Suspicious IP.\n'
        else:
            kml += 'Malicious Virus Detected.\n'

        kml += '</description>\n'

    elif suspicious:
        kml += '<styleUrl>#yellowLine</styleUrl>\n'  # Yellow line style for suspicious traffic
        kml += '<description>\n'
        kml += 'Suspicious IP.\n'
        kml += 'No malicious activity.\n'
        kml += '</description>\n'
    else:
        kml += '<styleUrl>#greenLine</styleUrl>\n'  # Green line style for clean traffic
        kml += '<description>\n'
        kml += 'No malicious activity.\n'
        kml += '</description>\n'

    kml += '<LineString>\n' \
           '<extrude>1</extrude>\n' \
           '<tessellate>1</tessellate>\n' \
           '<coordinates>\n' \
           f'{dst_coordinates[1]},{dst_coordinates[0]}\n' \
           f'{src_coordinates[1]},{src_coordinates[0]}\n' \
           '</coordinates>\n' \
           '</LineString>\n' \
           '</Placemark>\n'

    return kml  # Return the complete KML content


def process_packet(packet_data):
    try:
        if packet_data is None:
            return None

        (ts, buf) = packet_data
        eth = dpkt.ethernet.Ethernet(buf)

        # Skip non-IP packets
        if not isinstance(eth.data, dpkt.ip.IP):
            return None

        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)

        src_coordinates = get_coordinates(src)
        dst_coordinates = get_coordinates(dst)

        kml_point = ""

        packet_payload = get_packet_payload(ip)
        payload_decoded = detect_encoding(packet_payload)
        
        if not packet_payload:
            return None

        if is_suspicious_ip(dst) == 'suspicious':
            suspicious_ips.add(dst)

        # Extract session key
        session_key = '-'.join([src, dst, str(ip.data.sport), str(ip.data.dport)])
        reverse_session_key = '-'.join([dst, src, str(ip.data.dport), str(ip.data.sport)])

        # Check if the session key exists in malicious_files
        virus_info = None
        for entry in malicious_files:
            if entry.session_key in [session_key, reverse_session_key]:
                virus_info = entry
                break

        if virus_info:
            # If virus info found, generate kml for malicious IP
            kml_point += generate_kml_for_ips(dst_coordinates, src_coordinates, dst, malicious=True,
                                              virus_name=virus_info.virus_name, virus_type=virus_info.virus_type,
                                              virus_family=virus_info.virus_family)
        elif check_url_domains(payload_decoded, dst, dst_coordinates, src_coordinates):
            kml_point += generate_kml_for_ips(dst_coordinates, src_coordinates, dst, malicious=True,
                                              virus_name=None, virus_type=None, virus_family=None)
        elif dst in suspicious_ips or src in malicious_ips or is_suspicious_ip(src) == 'malicious':
            kml_point += generate_kml_for_ips(dst_coordinates, src_coordinates, dst, suspicious=True)
        else:
            kml_point += generate_kml_for_ips(dst_coordinates, src_coordinates, dst)

        return kml_point

    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
        return None


def generate_kml(pcap_data):
    pcap_file = io.BytesIO(pcap_data)
    pcap = dpkt.pcap.Reader(pcap_file)
    kml_pts = []

    num_threads = multiprocessing.cpu_count()  # Number of threads to use for processing packets
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_threads)

    # Start the packet processing threads
    packet_futures = []
    for packet_data in pcap:
        future = executor.submit(process_packet, packet_data)
        packet_futures.append(future)

    # Process the results as they become available
    for future in concurrent.futures.as_completed(packet_futures):
        point = future.result()
        if point:
            kml_pts.append(point)

    kml_header = '''<?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
    <Document>
        <name>Private Network Traffic</name>

        <Style id="greenLine">
            <LineStyle>
                <color>ff009900</color>
                <width>4</width>
            </LineStyle>
        </Style>

        <Style id="redLine">
            <LineStyle>
                <color>ff0000ff</color>
                <width>4</width>
            </LineStyle>
        </Style>

        <Style id="yellowLine">
            <LineStyle>
                <color>ff00ffff</color>
                <width>4</width>
            </LineStyle>
        </Style>
    '''

    kml_footer = '</Document></kml>'

    kmldoc = kml_header + ''.join(kml_pts) + kml_footer
    return kmldoc


# Compile the regular expression pattern once
LAT_LNG_PATTERN = re.compile(r"lat:\s*(-?\d+\.\d+),\s*lng:\s*(-?\d+\.\d+)")

# Create a dictionary to serve as the cache
coordinates_cache = {}


def get_coordinates_from_html(html_content):
    match = LAT_LNG_PATTERN.search(html_content)
    if match:
        latitude = float(match.group(1))
        longitude = float(match.group(2))
        return latitude, longitude
    else:
        return None, None


def get_coordinates(ip_address):
    if ip_address == 'Your_Private_IP':
        ip_address = 'your_Public_IP'

    # Check if coordinates are already cached
    if ip_address in coordinates_cache:
        return coordinates_cache[ip_address]

    url = f"https://whatismyip.live/ip/{ip_address}"
    response = requests.get(url)

    if response.ok:
        html_content = response.text
        latitude, longitude = get_coordinates_from_html(html_content)

        if latitude and longitude:
            # Cache the result
            coordinates_cache[ip_address] = (latitude, longitude)
            return latitude, longitude

    # Return early for error cases
    print(f"Error getting coordinates for IP {ip_address}: Latitude and longitude not found.")
    return None, None


def get_packet_payload(ip):
    if isinstance(ip, dpkt.ethernet.Ethernet):
        eth = ip
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.tcp.TCP) and hasattr(ip.data, 'data') and isinstance(ip.data.data, bytes):
                return bytes(ip.data.data)
            elif isinstance(ip.data, dpkt.icmp.ICMP) and hasattr(ip.data, 'data') and isinstance(ip.data.data, bytes):
                return bytes(ip.data.data)
    elif isinstance(ip, dpkt.ip.IP):
        if isinstance(ip.data, dpkt.tcp.TCP) and hasattr(ip.data, 'data') and isinstance(ip.data.data, bytes):
            return bytes(ip.data.data)
        elif isinstance(ip.data, dpkt.icmp.ICMP) and hasattr(ip.data, 'data') and isinstance(ip.data.data, bytes):
            return bytes(ip.data.data)
        elif isinstance(ip.data, dpkt.http.Request) and hasattr(ip.data, 'body') and isinstance(ip.data.body, bytes):
            return bytes(ip.data.body)
        elif isinstance(ip.data, dpkt.http.Response) and hasattr(ip.data, 'body') and isinstance(ip.data.body, bytes):
            return bytes(ip.data.body)

    return b''  # Return empty byte payload if it cannot be determined


def detect_encoding(payload):
    try:
        if isinstance(payload, bytes):
            result = chardet.detect(payload)
            encoding = result['encoding']
            if encoding is None:
                encoding = 'utf-8'  # Fallback to UTF-8 if encoding detection fails
            payload_decoded = payload.decode(encoding, errors='replace')
        else:
            payload_decoded = payload  # Payload is already a string, no need to decode

    except Exception as e:
        print(f"Error detecting encoding: {e}")
        encoding = 'utf-8'  # Fallback to UTF-8 in case of an error
        payload_decoded = payload.decode(encoding, errors='replace')  # Fallback to decoding with UTF-8

    return payload_decoded


def check_file_hashes(session_key, sha256_hash):
    global LOOKUP_COUNTER, LOOKUP_RESET_TIME, malicious_files

    # Check if the rate limit for the current minute has been reached
    if LOOKUP_COUNTER >= MAX_LOOKUPS_PER_MINUTE:
        current_time = int(time.time())
        if current_time < LOOKUP_RESET_TIME:
            wait_time = LOOKUP_RESET_TIME - current_time + 1
            print(f"Rate limit reached. Waiting for {wait_time} seconds before continuing.")
            time.sleep(wait_time)
            LOOKUP_COUNTER = 0

    # Check if the daily quota has been reached
    if LOOKUP_COUNTER >= MAX_LOOKUPS_PER_DAY:
        print("Daily quota reached. No more lookups allowed for today.")
        return False, None, None, None, None

    # Check if the monthly quota has been reached
    if LOOKUP_COUNTER >= MAX_LOOKUPS_PER_MONTH:
        print("Monthly quota reached. No more lookups allowed for this month.")
        return False, None, None, None, None

    file_hashes = [sha256_hash]

    for file_hash in file_hashes:
        headers = {
            "x-apikey": VT_API_KEY
        }
        params = {
            "apikey": VT_API_KEY,
            "resource": file_hash
        }

        response = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, params=params)
        LOOKUP_COUNTER += 1

        if response.status_code == 200:
            json_response = response.json()
            if "data" in json_response:
                data = json_response["data"]
                if "attributes" in data and "last_analysis_stats" in data["attributes"]:
                    last_analysis_stats = data["attributes"]["last_analysis_stats"]
                    if last_analysis_stats.get("malicious", 0) > 0:
                        virus_name = data.get("attributes", {}).get("popular_threat_classification", {}).get(
                            "suggested_threat_label")
                        virus_type = data.get("attributes", {}).get("popular_threat_classification", {}).get(
                            "popular_threat_category", [])
                        virus_type_names = [item["value"] for item in virus_type]
                        virus_family = data.get("attributes", {}).get("popular_threat_classification", {}).get(
                            "popular_threat_name", [])
                        virus_family_names = [item["value"] for item in virus_family]

                        if virus_name or virus_type_names or virus_family_names:
                            print(f"Virus detected: Name: {virus_name}, "
                                  f"Type: {', '.join(virus_type_names)}, "
                                  f"Family: {', '.join(virus_family_names)}")

                            # Convert lists to tuples
                            virus_type_names = tuple(virus_type_names)
                            virus_family_names = tuple(virus_family_names)

                            # Store information in the malicious_files set
                            malicious_info = MaliciousFile(session_key=session_key, virus_name=virus_name,
                                                           virus_type=virus_type_names, virus_family=virus_family_names)
                            malicious_files.add(malicious_info)

                            return True, virus_type_names, virus_name, virus_family_names, session_key

    return False, None, None, None, None


def check_url_domains(payload_decoded, ip, dst_coordinates, src_coordinates):
    url_regex = r'https?://([\w\-\.]+)/?'

    urls = re.findall(url_regex, payload_decoded)
    for url in urls:
        domain = url.split('/')[0]
        print(f"Checking URL '{url}' in OTX API...")
        url_to_check = f'http://{domain}'  # Construct the URL to check
        url = f'{base_url}/indicators/url/{url_to_check}/general'  # Construct the request URL

        headers = {'X-OTX-API-KEY': OTX_API_KEY}  # Add the API key to the headers

        response = requests.get(url, headers=headers)  # Send the GET request to OTX

        if response.status_code == 200:
            data = json.loads(response.text)
            if data['pulse_info']['count'] > 0:
                print(f"The URL '{url_to_check}' was found malicious!")
                return generate_kml_for_ips(dst_coordinates, src_coordinates, ip, url=url_to_check, malicious=True)

            else:
                print(f"The URL '{url_to_check}' is not malicious.")

        else:
            print(f"Failed to retrieve information from OTX for URL: {url_to_check}")

    return False  # No malware detected


def is_suspicious_ip(ip_address):
    try:
        reversed_ip = '.'.join(reversed(ip_address.split('.'))) + '.zen.spamhaus.org'
        _, _, _, _, addr = socket.getaddrinfo(reversed_ip, None)[0]
        addr_str = str(addr)  # Convert addr to a string
        if addr_str == '127.0.0.2' or addr_str == '127.0.0.3':
            return 'suspicious'
        elif addr_str.startswith(('127.0.0.4', '127.0.0.5', '127.0.0.6', '127.0.0.7')):
            return 'malicious'
        elif addr_str.startswith(('127.0.0.10', '127.0.0.11')):
            return 'malicious'
        else:
            return 'clean'
    except (socket.gaierror, IndexError):
        return 'clean'


def write_kml_file(kmldoc, file_path):
    with open(file_path, 'w') as f:
        f.write(kmldoc)


if __name__ == '__main__':
    main()
