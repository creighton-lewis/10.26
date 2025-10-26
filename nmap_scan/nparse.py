#!/usr/bin/env python3
import xml.etree.ElementTree as ET
import sys

def parse_nmap_xml(xml_file):
    try:
        ## Parse the XML file
        tree = ET.parse(xml_file)
        root = tree.getroot()

        ## Print scan information
        print("Nmap Scan Report")
        print("=" * 50)
        print(f"Scan started at: {root.get('startstr')}")
        print(f"Nmap version: {root.get('version')}")
        print(f"Nmap command: {root.get('args')}")
        print("=" * 50)

        ## Process each host in the scan
        for host in root.findall('host'):
            ## Get host addresses
            for addr in host.findall('address'):
                if addr.get('addrtype') == 'ipv4':
                    ip_address = addr.get('addr')
                    print(f"\nHost: {ip_address}")

            ## Get hostname if available
            hostnames = host.find('hostnames')
            if hostnames is not None:
                for hostname in hostnames.findall('hostname'):
                    print(f"Hostname: {hostname.get('name')}")

            ## Get host status
            status = host.find('status')
            if status is not None:
                print(f"Status: {status.get('state')}")

            ## Process ports
            ports = host.find('ports')
            if ports is not None:
                print("\nOpen Ports:")
                print("-" * 50)
                print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION'}")
                print("-" * 50)

                for port in ports.findall('port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')

                    ## Get port state
                    state = port.find('state')
                    port_state = state.get('state') if state is not None else "unknown"

                    ## Skip closed ports
                    if port_state != "open":
                        continue

                    ## Get service information
                    service = port.find('service')
                    if service is not None:
                        service_name = service.get('name', '')
                        service_product = service.get('product', '')
                        service_version = service.get('version', '')
                        service_info = f"{service_product} {service_version}".strip()
                    else:
                        service_name = ""
                        service_info = ""

                    print(f"{port_id}/{protocol:<5} {port_state:<10}{service_name:<15}{service_info}")

            ## Get OS detection information
            os = host.find('os')
            if os is not None:
                print("\nOS Detection:")
                for osmatch in os.findall('osmatch'):
                    print(f"OS: {osmatch.get('name')} (Accuracy: {osmatch.get('accuracy')}%)")

    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

    return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <nmap_xml_file>")
        sys.exit(1)

    xml_file = sys.argv[1]
    if not parse_nmap_xml(xml_file):
        sys.exit(1)