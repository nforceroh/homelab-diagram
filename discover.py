#!/usr/bin/env python3
"""
Homelab Discovery Script

Queries homelab infrastructure devices (OPNsense, Brocade switches, OpenWrt APs,
Linux servers with Kubernetes) and populates inventory.yaml with the details.

Usage:
    python3 discover.py [--credentials CREDENTIALS_FILE] [--output INVENTORY_FILE]

    --credentials  Path to credentials YAML file (default: credentials.yaml)
    --output       Path to output inventory YAML (default: inventory.yaml)
    --dry-run      Don't write to output file, just print discovered data
    --verbose      Show detailed output

Security notes:
    - Never commit credentials.yaml to version control
    - Use SOPS to encrypt: sops --encrypt credentials.yaml > credentials.yaml.enc
    - Use SOPS to decrypt: sops --decrypt credentials.yaml.enc > credentials.yaml
    - Or use environment variables for credentials
"""

import argparse
import sys
import yaml
import json
import os
import socket
import subprocess
from pathlib import Path

# Try to import sops-decrypted data; fall back to direct YAML reading
try:
    from sops import decrypt
    HAS_SOPS = True
except ImportError:
    HAS_SOPS = False


def load_credentials(credential_path):
    """Load credentials from YAML file, potentially encrypted with SOPS."""
    cred_file = Path(credential_path)
    
    if not cred_file.exists():
        print(f"❌ Credentials file not found: {credential_path}", file=sys.stderr)
        print("   Create from: credentials.yaml.template", file=sys.stderr)
        sys.exit(1)
    
    # Try SOPS decryption first if available
    if HAS_SOPS and cred_file.suffix == '.enc':
        try:
            with open(cred_file, 'r') as f:
                encrypted_data = f.read()
            decrypted = decrypt(encrypted_data)
            cred_data = yaml.safe_load(decrypted)
            print("✅ Credentials decrypted with SOPS")
            return cred_data
        except Exception as e:
            print(f"⚠️  SOPS decryption failed: {e}", file=sys.stderr)
            print("   Falling back to raw YAML reading...", file=sys.stderr)
    
    # Read raw YAML
    try:
        with open(cred_file, 'r') as f:
            cred_data = yaml.safe_load(f)
        print("✅ Credentials loaded from YAML")
        return cred_data
    except Exception as e:
        print(f"❌ Failed to read credentials YAML: {e}", file=sys.stderr)
        sys.exit(1)


def discover_opnsense(creds, inv):
    """Discover OPNsense firewall details via API."""
    print("\n🔍 Discovering OPNsense...")
    
    api_url = creds["opnsense"]["api_url"]
    api_key = creds["opnsense"]["api_key"]
    api_secret = creds["opnsense"]["api_secret"]
    
    headers = {
        "Content-Type": "application/json",
    }
    
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        payload = {
            "id": 1,
            "method": "system.info",
            "params": []
        }
        
        resp = requests.post(api_url, json=payload, headers=headers, timeout=30, verify=False)
        data = resp.json()
        
        if "result" in data:
            info = data["result"]
            inv["opnsense"] = {
                "name": "OPNsense",
                "type": "router/firewall",
                "model": info.get("model", "Unknown"),
                "os": f"OPNsense {info.get('version', 'X.Y')}",
                "hw": [
                    {"icon": "glyph-cpu", "label": "CPU", "value": info.get("cpu", "Unknown"), "sub": f"{info.get('cpu_cores', '?')} cores · {info.get('cpu_threads', '?')} threads"},
                    {"icon": "glyph-ram", "label": "MEMORY", "value": info.get("memory", "Unknown"), "sub": f"{info.get('memory_total', '?')} total"},
                    {"icon": "glyph-nic", "label": "NETWORK", "value": info.get("wan_ipaddr", "Unknown"), "sub": f"{info.get('lan_ipaddr', '?')} LAN"},
                ],
                "ip": creds["opnsense"].get("ip", "10.0.99.1"),
                "internal": "opnsense",
                "nic_note": f"LACP · {info.get('wan_if', '?')} interface",
                "services": [
                    {"icon": "adguard", "name": "AdGuard Home", "note": "DNS for all VLANs"},
                    {"icon": "glyph-dhcp", "name": "dnsmasq", "note": "DHCP + *.internal"},
                    {"icon": "wireguard", "name": "WireGuard", "note": "wg0 · UDP 51820"},
                    {"icon": "glyph-shield", "name": "Suricata IPS", "note": "outbound inspection"},
                    {"icon": "crowdsec", "name": "CrowdSec", "note": "LAPI + pf bouncer"},
                    {"icon": "glyph-block", "name": "pf blocklist", "note": "~2.3k bad IPs on WAN"},
                ],
            }
            print(f"  ✅ OPNsense: {info.get('version', '?')} - {info.get('model', '?')}")
        else:
            print(f"  ⚠️  OPNsense API returned: {data}", file=sys.stderr)
            inv["opnsense"] = {"name": "OPNsense", "type": "router/firewall", "model": "Unknown", "os": "OPNsense X.Y"}
            
    except ImportError:
        print("  ⚠️  'requests' not installed, using template for OPNsense", file=sys.stderr)
        inv["opnsense"] = {"name": "OPNsense", "type": "router/firewall", "model": "Unknown", "os": "OPNsense X.Y"}
    except Exception as e:
        print(f"  ❌ OPNsense discovery error: {e}", file=sys.stderr)
        inv["opnsense"] = {"name": "OPNsense", "type": "router/firewall", "model": "Unknown", "os": "OPNsense X.Y"}
    
    return inv


def discover_brocade_switches(creds, inv):
    """Discover Brocade switch details via SSH."""
    print("\n🔍 Discovering Brocade switches...")
    
    switches = creds.get("switches", [])
    
    for sw in switches:
        name = sw.get("name", "unknown")
        model = sw.get("model", "Brocade switch")
        ssh_host = sw.get("ssh_host", "10.0.99.2")
        ssh_user = sw.get("ssh_user", "admin")
        ssh_password = sw.get("ssh_password", None)
        ssh_key_path = sw.get("ssh_key_path", "~/.ssh/id_rsa")
        
        print(f"  📡 Discovering {name} at {ssh_host}...")
        
        try:
            import paramiko
            
            # Create transport with legacy KEX and cipher support for Brocade switches
            sock = socket.create_connection((ssh_host, 22), timeout=30)
            transport = paramiko.Transport(sock)
            transport.get_security_options().kex = [
                'diffie-hellman-group14-sha1',
                'diffie-hellman-group1-sha1',
                'diffie-hellman-group-exchange-sha1',
                'diffie-hellman-group-exchange-sha256',
                'diffie-hellman-group14-sha256',
                'diffie-hellman-group16-sha512',
                'ecdh-sha2-nistp256',
                'ecdh-sha2-nistp384',
                'ecdh-sha2-nistp521',
            ]
            transport.get_security_options().ciphers = [
                'aes128-ctr',
                'aes192-ctr',
                'aes256-ctr',
                'aes128-cbc',
                'aes192-cbc',
                'aes256-cbc',
                '3des-cbc',
            ]
            
            # Brocade switches only support password auth
            if not ssh_password:
                raise Exception("No password provided for Brocade switch")
            
            try:
                transport.connect(username=ssh_user, password=ssh_password)
            except Exception as e:
                raise Exception(f"SSH connection failed: {e}")
            
            ssh = paramiko.SSHClient()
            ssh._transport = transport
            
            # Get switch model and OS version
            stdin, stdout, stderr = ssh.exec_command("display basic")
            output = stdout.read().decode('utf-8', errors='replace')
            
            parsed_model = model
            parsed_os = "Brocade switch OS"
            
            for line in output.split('\n'):
                line = line.strip()
                if "Model" in line or "Part number" in line:
                    parsed_model = line.split(":")[-1].strip() if ":" in line else parsed_model
                if "Version" in line or "Software" in line:
                    parsed_os = line.split(":")[-1].strip() if ":" in line else parsed_os
            
            # Get interface information - use shell channel for Brocade switches
            try:
                stdin, stdout, stderr = ssh.exec_command("display interface brief", timeout=10)
                port_output = stdout.read().decode('utf-8', errors='replace')
            except Exception as e:
                # If exec_command fails, try using a shell channel
                try:
                    shell = ssh.invoke_shell()
                    shell.send("display interface brief\n")
                    import time
                    time.sleep(2)
                    port_output = ""
                    while shell.recv_ready():
                        port_output += shell.recv(4096).decode('utf-8', errors='replace')
                    shell.close()
                except:
                    port_output = ""
            
            ports = []
            for line in port_output.split('\n'):
                line = line.strip()
                parts = line.split()
                if len(parts) >= 3 and ("Eth" in parts[0] or "port" in parts[0].lower()):
                    port_name = parts[0]
                    status = parts[1] if len(parts) > 1 else "down"
                    speed = parts[2] if len(parts) > 2 else "unknown"
                    
                    tagged_vlans = []
                    untagged_vlan = "none"
                    
                    if len(parts) > 3:
                        remaining = parts[3:]
                        for r in remaining:
                            if r.startswith("VLAN") or r.isdigit():
                                if r.startswith("VLAN"):
                                    tagged_vlans.append(r)
                                elif r.isdigit():
                                    if untagged_vlan == "none":
                                        untagged_vlan = r
                    
                    connected = status.upper() == "UP"
                    
                    ports.append({
                        "name": port_name,
                        "to": "free" if not connected else "device",
                        "tagged": tagged_vlans[:5],
                        "untagged": untagged_vlan,
                    })
            
            sw_entry = {
                "name": name,
                "type": "switch",
                "model": parsed_model,
                "os": parsed_os,
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "config": "configured as pure L2 switch",
                "ports": ports[:10],
            }
            
            inv[f"switch_{name.lower().replace(' ', '_')}"] = sw_entry
            print(f"  ✅ {name}: model={parsed_model}, os={parsed_os}, ports={len(sw_entry['ports'])}")
            
        except ImportError:
            print(f"  ⚠️  'paramiko' not installed, using template for {name}", file=sys.stderr)
            sw_key = f"switch_{name.lower().replace(' ', '_')}"
            inv[sw_key] = {
                "name": name,
                "type": "switch",
                "model": model,
                "os": "Switch OS version",
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "config": "configured as pure L2 switch",
                "ports": sw.get("ports", []),
            }
        except Exception as e:
            import traceback
            print(f"  ❌ {name} discovery error: {e}", file=sys.stderr)
            if "--verbose" in sys.argv:
                traceback.print_exc()
            sw_key = f"switch_{name.lower().replace(' ', '_')}"
            inv[sw_key] = {
                "name": name,
                "type": "switch",
                "model": model,
                "os": "Switch OS version",
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "config": "configured as pure L2 switch",
                "ports": sw.get("ports", []),
            }
    
    return inv


def discover_openwrt_aps(creds, inv):
    """Discover OpenWrt access points via SSH."""
    print("\n🔍 Discovering OpenWrt access points...")
    
    aps = creds.get("access_points", [])
    
    for ap in aps:
        name = ap.get("name", "unknown-ap")
        ssh_host = ap.get("ssh_host", "10.0.10.1")
        ssh_user = ap.get("ssh_user", "root")
        ssh_key_path = ap.get("ssh_key_path", "~/.ssh/id_rsa")
        ssh_password = ap.get("ssh_password", None)
        
        print(f"  📡 Discovering {name} at {ssh_host}...")
        
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if ssh_password:
                ssh.connect(ssh_host, username=ssh_user, password=ssh_password, timeout=30, disabled_algorithms={'kex': []})
            elif ssh_key_path:
                key = paramiko.RSAKey.from_private_key_file(os.path.expanduser(ssh_key_path))
                ssh.connect(ssh_host, username=ssh_user, pkey=key, timeout=30, disabled_algorithms={'kex': []})
            else:
                ssh.connect(ssh_host, username=ssh_user, timeout=30, disabled_algorithms={'kex': []})
            
            # Get system information via uci
            stdin, stdout, stderr = ssh.exec_command("uci show system.@system[0] 2>/dev/null")
            system_output = stdout.read().decode('utf-8', errors='replace')
            
            # Get wireless configuration
            stdin, stdout, stderr = ssh.exec_command("uci show wireless 2>/dev/null | head -50")
            wireless_output = stdout.read().decode('utf-8', errors='replace')
            
            model_info = {"model": ap.get("model", "OpenWrt x86_64"), "hostname": "openwrt"}
            
            for line in system_output.split('\n'):
                if "hostname" in line.lower():
                    val = line.split("=")[-1].strip().strip('"').strip("'")
                    if val:
                        model_info["hostname"] = val
                if "model" in line.lower() and "=" in line:
                    val = line.split("=")[-1].strip().strip('"').strip("'")
                    if val:
                        model_info["model"] = val
            
            # Count radios and SSIDs
            radios = wireless_output.count("config wifi-device") if "config wifi-device" in wireless_output else 0
            ssids = wireless_output.count("ssid") // 2 if "ssid" in wireless_output else 0
            
            ssh.close()
            
            ap_entry = {
                "name": name,
                "type": "access point",
                "model": model_info["model"],
                "vlan": ap.get("vlan", "10"),
                "trunk": ap.get("trunk", False),
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "icons": [ap.get("icons", "openwrt")],
                "hw": {
                    "hostname": model_info.get("hostname", "openwrt"),
                    "radios": radios,
                    "ssids": ssids,
                },
            }
            
            if ssids > 0:
                ap_entry["ssids"] = ap.get("ssids", [])
            
            inv[f"ap_{name.lower().replace(' ', '_')}"] = ap_entry
            print(f"  ✅ {name}: model={model_info['model']}, VLAN={ap.get('vlan', '10')}, radios={radios}, SSIDs={ssids}")
            
        except ImportError:
            print(f"  ⚠️  'paramiko' not installed, using template for {name}", file=sys.stderr)
            ap_key = f"ap_{name.lower().replace(' ', '_')}"
            inv[ap_key] = {
                "name": name,
                "type": "access point",
                "model": ap.get("model", "OpenWrt x86_64"),
                "vlan": ap.get("vlan", "10"),
                "trunk": ap.get("trunk", False),
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "icons": [ap.get("icons", "openwrt")],
            }
        except Exception as e:
            print(f"  ❌ {name} discovery error: {e}", file=sys.stderr)
            ap_key = f"ap_{name.lower().replace(' ', '_')}"
            inv[ap_key] = {
                "name": name,
                "type": "access point",
                "model": ap.get("model", "OpenWrt x86_64"),
                "vlan": ap.get("vlan", "10"),
                "trunk": ap.get("trunk", False),
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "icons": [ap.get("icons", "openwrt")],
            }
    
    return inv


def discover_linux_servers(creds, inv):
    """Discover Linux servers and their Kubernetes clusters."""
    print("\n🔍 Discovering Linux servers...")
    
    servers = creds.get("linux_servers", [])
    
    for server in servers:
        name = server.get("name", "unknown-server")
        ssh_host = server.get("ssh_host", "10.0.10.50")
        ssh_user = server.get("ssh_user", "discovery")
        ssh_key_path = server.get("ssh_key_path", "~/.ssh/id_rsa")
        ssh_password = server.get("ssh_password", None)
        
        print(f"  📡 Discovering {name} at {ssh_host}...")
        
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if ssh_password:
                ssh.connect(ssh_host, username=ssh_user, password=ssh_password, timeout=30, disabled_algorithms={'kex': []})
            elif ssh_key_path:
                key = paramiko.RSAKey.from_private_key_file(os.path.expanduser(ssh_key_path))
                ssh.connect(ssh_host, username=ssh_user, pkey=key, timeout=30, disabled_algorithms={'kex': []})
            else:
                ssh.connect(ssh_host, username=ssh_user, timeout=30, disabled_algorithms={'kex': []})
            
            # Get OS information
            stdin, stdout, stderr = ssh.exec_command("cat /etc/os-release 2>/dev/null || uname -srm")
            os_output = stdout.read().decode('utf-8', errors='replace')
            
            # Get Docker containers if Docker is running
            containers = []
            try:
                stdin, stdout, stderr = ssh.exec_command("docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null")
                container_output = stdout.read().decode('utf-8', errors='replace')
                if container_output.strip():
                    for line in container_output.strip().split('\n'):
                        parts = line.split()
                        if len(parts) >= 2:
                            containers.append({
                                "name": parts[0],
                                "image": parts[1],
                                "ports": " ".join(parts[2:]) if len(parts) > 2 else "",
                            })
            except Exception:
                pass
            
            # Get Kubernetes information
            k8s_info = {"cluster_name": None, "master_ip": None, "services": []}
            try:
                stdin, stdout, stderr = ssh.exec_command("kubectl cluster-info 2>/dev/null || echo 'no-kubectl'")
                k8s_output = stdout.read().decode('utf-8', errors='replace')
                if "error" not in k8s_output.lower() and "no-kubectl" not in k8s_output.lower():
                    k8s_info["cluster_info"] = k8s_output.strip()
            except Exception:
                pass
            
            # Get node information
            try:
                stdin, stdout, stderr = ssh.exec_command("kubectl get nodes -o wide 2>/dev/null || echo 'no-kubectl'")
                node_output = stdout.read().decode('utf-8', errors='replace')
                if "no-kubectl" not in node_output:
                    k8s_info["nodes"] = node_output.strip()
            except Exception:
                pass
            
            ssh.close()
            
            server_entry = {
                "name": name,
                "type": "server",
                "model": server.get("model", "Custom Linux Server"),
                "os": os_output.strip()[:100] if os_output else "Linux",
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "icons": server.get("icons", ["linux"]),
                "services": server.get("services", []),
                "containers": containers,
                "kubernetes": k8s_info,
            }
            
            inv[f"server_{name.lower().replace(' ', '_')}"] = server_entry
            print(f"  ✅ {name}: OS={os_output.strip()[:50] if os_output else 'Linux'}, containers={len(containers)}, k8s={k8s_info.get('cluster_info', 'none')[:30] if k8s_info.get('cluster_info') else 'none'}")
            
        except ImportError:
            print(f"  ⚠️  'paramiko' not installed, using template for {name}", file=sys.stderr)
            server_key = f"server_{name.lower().replace(' ', '_')}"
            inv[server_key] = {
                "name": name,
                "type": "server",
                "model": server.get("model", "Custom Linux Server"),
                "os": "Linux",
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "icons": server.get("icons", ["linux"]),
                "services": server.get("services", []),
            }
        except Exception as e:
            print(f"  ❌ {name} discovery error: {e}", file=sys.stderr)
            server_key = f"server_{name.lower().replace(' ', '_')}"
            inv[server_key] = {
                "name": name,
                "type": "server",
                "model": server.get("model", "Custom Linux Server"),
                "os": "Linux",
                "ip": ssh_host,
                "internal": name.lower().replace(" ", ""),
                "icons": server.get("icons", ["linux"]),
                "services": server.get("services", []),
            }
    
    return inv


def main():
    parser = argparse.ArgumentParser(
        description="Homelab Discovery Script"
    )
    parser.add_argument(
        "--credentials", 
        default="credentials.yaml",
        help="Path to credentials YAML file (default: credentials.yaml)"
    )
    parser.add_argument(
        "--output", 
        default="inventory.yaml",
        help="Path to output inventory YAML (default: inventory.yaml)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't write to output file, just print discovered data"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    
    args = parser.parse_args()
    
    # Load credentials
    creds = load_credentials(args.credentials)
    
    # Initialize inventory with meta and default sections
    inv = {
        "meta": {
            "title": "My Homelab",
            "title_redacted": "My Homelab",
            "date": "November 2026",
            "watermark": "u/goblinmine",
            "domain": creds.get("domain", "example.com"),
        },
        "redact": {
            "domain": True,
            "domain_placeholder": "redacted.com",
            "ssid_names": True,
        },
        # VLAN definitions (order matters for the legend)
        "vlans": [
            {"key": "10", "tag": "VLAN 10", "name": "LAN", "subnet": "10.0.10.0/24", "color": "#58a6ff", "note": "trusted · may manage the other VLANs"},
            {"key": "20", "tag": "VLAN 20", "name": "DMZ", "subnet": "10.0.20.0/24", "color": "#f0883e", "note": "services · no access to LAN, GUEST or MGMT"},
            {"key": "30", "tag": "VLAN 30", "name": "GUEST", "subnet": "10.0.30.0/24", "color": "#bc8cff", "note": "internet only · plus the NAS public share"},
            {"key": "40", "tag": "VLAN 40", "name": "IoT", "subnet": "10.0.40.0/24", "color": "#3fb950", "note": "internet only · HA gets a few narrow holes"},
            {"key": "99", "tag": "VLAN 99", "name": "MGMT", "subnet": "10.0.99.0/24", "color": "#e3b341", "note": "admin interfaces · only from LAN and VPN"},
            {"key": "vpn", "tag": "WireGuard", "name": "VPN", "subnet": "10.0.50.0/24", "color": "#39c5cf", "note": "split tunnel · LAN-like access, no internet"},
            {"key": "wan", "tag": "Fritzbox", "name": "WAN", "subnet": "192.168.178.0/24", "color": "#f85149", "note": "untrusted · OPNsense's uplink to the Fritzbox"},
        ],
        "internet": {
            "speed": {"down": "600 Mbit/s", "up": "50 Mbit/s"},
            "cloud_services": [
                {"icon": "cloudflare", "name": "Cloudflare", "note": "DNS · *.{domain} · DNS-01 wildcard cert"},
                {"icon": "backblaze", "name": "Backblaze B2", "note": "offsite copy of NAS data"},
            ],
        },
        "devices": {},
        "ssids": [
            {"name": "Home", "redacted": "Home", "vlan": "10"},
            {"name": "Guest", "redacted": "Guest", "vlan": "30"},
            {"name": "IoT", "redacted": "IoT", "vlan": "40"},
        ],
        "remote": {"name": "Remote access", "note": "phone + laptop · WireGuard VPN"},
        "port_forwards": [
            {"port": "80, 443", "proto": "TCP/UDP", "to": "Traefik", "what": "every *.{domain} site"},
            {"port": "22", "proto": "TCP", "to": "Forgejo", "what": "git over SSH (→ :2222)"},
            {"port": "1024", "proto": "TCP", "to": "TrueNAS", "what": "key-only SFTP backups"},
            {"port": "51820", "proto": "UDP", "to": "WireGuard", "what": "remote access VPN"},
            {"port": "64001", "proto": "TCP/UDP", "to": "qBittorrent", "what": "incoming peers"},
        ],
    }
    
    # Discover devices based on prioritization
    prioritize = creds.get("prioritize_devices", ["opnsense", "switches", "access_points", "linux_servers"])
    
    print("=" * 60)
    print("Homelab Discovery Script")
    print("=" * 60)
    print(f"Credentials: {args.credentials}")
    print(f"Output: {args.output}")
    print(f"Prioritize: {prioritize}")
    print("=" * 60)
    
    for device_type in prioritize:
        if device_type == "opnsense":
            inv = discover_opnsense(creds, inv)
        elif device_type == "switches":
            inv = discover_brocade_switches(creds, inv)
        elif device_type == "access_points":
            inv = discover_openwrt_aps(creds, inv)
        elif device_type == "linux_servers":
            inv = discover_linux_servers(creds, inv)
        else:
            print(f"⚠️  Unknown device type: {device_type}", file=sys.stderr)
    
    # Update meta date
    from datetime import datetime
    inv["meta"]["date"] = datetime.now().strftime("%B %Y")
    
    # Print summary
    print("\n" + "=" * 60)
    print("Discovered inventory sections:")
    print("=" * 60)
    
    discovered_sections = []
    for key in inv:
        if key in ("meta", "redact", "vlans", "internet", "devices", "ssids", "remote", "port_forwards"):
            continue
        if inv[key]:
            discovered_sections.append(key)
    
    for section in sorted(discovered_sections):
        item_count = len(inv[section]) if isinstance(inv[section], list) else 1
        print(f"  📦 {section}: {item_count} item(s)")
    
    print(f"  📦 devices: {len(inv.get('devices', {}))} device(s)")
    print(f"  📦 ssids: {len(inv.get('ssids', []))} SSID(s)")
    
    # Write output if not dry-run
    if not args.dry_run:
        output_path = Path(args.output)
        
        # Backup existing inventory if it exists and has content
        if output_path.exists() and output_path.stat().st_size > 0:
            backup_path = output_path.with_suffix('.yaml.backup')
            print(f"  📋 Backing up existing {args.output} to {backup_path}")
            subprocess.run(["cp", str(output_path), str(backup_path)], check=True)
        
        try:
            with open(output_path, 'w') as f:
                yaml.dump(inv, f, default_flow_style=False, sort_keys=False, width=float("inf"))
            print(f"\n✅ Inventory written to {args.output}")
            print(f"   (Remember to git-add and commit, or merge manually)")
        except Exception as e:
            print(f"\n❌ Failed to write inventory: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("\n🔍 Dry-run mode: no file written")
    
    print("\n" + "=" * 60)
    print("Discovery complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. Review the generated inventory.yaml")
    print("  2. Merge changes into your main inventory if needed")
    print("  3. Run: python3 build.py --inventory inventory.yaml")
    print("  4. Check: out/homelab.png for the diagram")
    print("=" * 60)


if __name__ == "__main__":
    main()
