#!/usr/bin/env python3
"""
Real-time Packet Sniffer Dashboard
Full-screen terminal dashboard with live network traffic analysis
"""

import subprocess
import json
import sys
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.console import Console
from rich.text import Text
import argparse
import threading
import select

console = Console()

# Global state for view mode
current_view = "overview"  # Can be: overview, protocols, talkers, domains, dns, recent, alerts, logs
split_mode = False
split_panels = []  # List of up to 4 panel names to show in split mode
help_mode = False  # Show keyboard shortcuts when True
paused = False  # Whether packet capture is paused

class PacketAnalyzer:
    def __init__(self, interface="wlp2s0", max_packets=1000):
        self.interface = interface
        self.packets = deque(maxlen=max_packets)
        self.start_time = time.time()
        
        # Log file for continuous writing
        self.log_file = open('packet_sniffer.log', 'w')
        self.log_file.write("=" * 80 + "\n")
        self.log_file.write("PACKET SNIFFER - LIVE RAW LOGS\n")
        self.log_file.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_file.write("=" * 80 + "\n\n")
        self.log_file.flush()
        
        # Statistics
        self.protocol_counts = Counter()
        self.ip_packet_counts = Counter()
        self.ip_byte_counts = Counter()
        self.domain_counts = Counter()
        self.dns_queries = Counter()
        
        # Recent activity (for display)
        self.recent_packets = deque(maxlen=10)
        
        # Raw logs (for debugging/inspection)
        self.raw_logs = deque(maxlen=50)
        
        # Security alerts
        self.alerts = deque(maxlen=5)
        
        # Performance metrics
        self.packet_times = deque(maxlen=100)
        self.byte_times = deque(maxlen=100)
        
    def add_packet(self, packet_data):
        """Process incoming packet"""
        try:
            # Store raw JSON for logs panel
            current_time = time.time()
            self.raw_logs.append({
                'time': current_time,
                'data': packet_data
            })
            
            # Write to log file
            timestamp = datetime.fromtimestamp(current_time).strftime('%H:%M:%S.%f')[:-3]
            try:
                parsed = json.loads(packet_data)
                formatted = json.dumps(parsed, indent=2)
                self.log_file.write(f"[{timestamp}]\n{formatted}\n\n")
            except:
                self.log_file.write(f"[{timestamp}]\n{packet_data}\n\n")
            self.log_file.flush()  # Ensure it's written immediately
            
            pkt = json.loads(packet_data)
            self.packets.append(pkt)
            current_time = time.time()
            
            # Update protocol stats
            protocol = pkt.get('protocol', 'Unknown')
            self.protocol_counts[protocol] += 1
            
            # Update IP stats
            src_ip = pkt.get('src_ip', '')
            dst_ip = pkt.get('dst_ip', '')
            pkt_len = pkt.get('length', 0)
            
            if src_ip:
                self.ip_packet_counts[src_ip] += 1
                self.ip_byte_counts[src_ip] += pkt_len
            if dst_ip:
                self.ip_packet_counts[dst_ip] += 1
                self.ip_byte_counts[dst_ip] += pkt_len
            
            # Track domains
            if 'domain' in pkt:
                self.domain_counts[pkt['domain']] += 1
            
            # Track DNS queries
            if 'dns_query' in pkt:
                self.dns_queries[pkt['dns_query']] += 1
            
            # Performance tracking
            self.packet_times.append(current_time)
            self.byte_times.append((current_time, pkt_len))
            
            # Add to recent packets
            self.recent_packets.append(pkt)
            
            # Security alerts
            self._check_security_alerts(pkt)
            
        except json.JSONDecodeError:
            pass
    
    def _check_security_alerts(self, pkt):
        """Check for suspicious activity"""
        # DNS tunneling detection (very long domains)
        if 'dns_query' in pkt and len(pkt['dns_query']) > 50:
            self.alerts.append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'type': 'DNS_TUNNEL',
                'msg': f"Suspicious long DNS query: {pkt['dns_query'][:30]}..."
            })
        
        # Uncommon protocol alert
        if pkt.get('protocol') in ['FTP']:
            self.alerts.append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'type': 'UNENCRYPTED',
                'msg': f"Unencrypted {pkt['protocol']} traffic detected"
            })
    
    def get_pps(self):
        """Calculate packets per second"""
        if len(self.packet_times) < 2:
            return 0
        time_window = self.packet_times[-1] - self.packet_times[0]
        if time_window == 0:
            return 0
        return len(self.packet_times) / time_window
    
    def get_bandwidth(self):
        """Calculate bandwidth (bytes/sec)"""
        if len(self.byte_times) < 2:
            return 0
        recent_bytes = [(t, b) for t, b in self.byte_times if t > time.time() - 1]
        if len(recent_bytes) < 2:
            return 0
        total_bytes = sum(b for _, b in recent_bytes)
        return total_bytes
    
    def format_bytes(self, bytes_val):
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"
    
    def reset(self):
        """Reset all statistics"""
        self.packets.clear()
        self.start_time = time.time()
        self.protocol_counts.clear()
        self.ip_packet_counts.clear()
        self.ip_byte_counts.clear()
        self.domain_counts.clear()
        self.dns_queries.clear()
        self.recent_packets.clear()
        self.raw_logs.clear()
        self.alerts.clear()
        self.packet_times.clear()
        self.byte_times.clear()
        
        # Reset log file
        self.log_file.close()
        self.log_file = open('packet_sniffer.log', 'w')
        self.log_file.write("=" * 80 + "\n")
        self.log_file.write("PACKET SNIFFER - LIVE RAW LOGS (RESET)\n")
        self.log_file.write(f"Reset at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_file.write("=" * 80 + "\n\n")
        self.log_file.flush()
    
    def get_formatted_logs(self):
        """Get all logs formatted for display"""
        output = []
        for log in self.raw_logs:
            timestamp = datetime.fromtimestamp(log['time']).strftime('%H:%M:%S.%f')[:-3]
            try:
                parsed = json.loads(log['data'])
                formatted = json.dumps(parsed, indent=2)
                output.append(f"[{timestamp}]\n{formatted}\n")
            except:
                output.append(f"[{timestamp}]\n{log['data']}\n")
        return "\n".join(output)

def create_header(analyzer):
    """Create header panel with key stats"""
    runtime = time.time() - analyzer.start_time
    pps = analyzer.get_pps()
    bw = analyzer.get_bandwidth()
    
    header_text = Text()
    header_text.append("🔍 PACKET SNIFFER DASHBOARD", style="bold cyan")
    header_text.append(f"\n Interface: {analyzer.interface}  ", style="dim")
    header_text.append(f"| Runtime: {int(runtime)}s  ", style="dim")
    header_text.append(f"| Total Packets: {len(analyzer.packets):,}  ", style="bold green")
    header_text.append(f"| PPS: {int(pps):,}  ", style="bold yellow")
    header_text.append(f"| Bandwidth: {analyzer.format_bytes(bw)}/s", style="bold magenta")
    
    # Show pause status
    if paused:
        header_text.append("  | ", style="dim")
        header_text.append("⏸️  PAUSED", style="bold yellow")
    
    # Add keyboard shortcuts help (only when help_mode is True)
    if help_mode:
        header_text.append("\n", style="dim")
        header_text.append("🎮 ", style="dim")
        header_text.append("[P]rotocols ", style="cyan")
        header_text.append("[T]alkers ", style="yellow")
        header_text.append("[D]omains ", style="blue")
        header_text.append("[N]S ", style="blue")
        header_text.append("[R]ecent ", style="green")
        header_text.append("[A]lerts ", style="red")
        header_text.append("[L]ogs ", style="white")
        header_text.append("| [O]verview ", style="white")
        header_text.append("[S]plit ", style="magenta")
        header_text.append("[Q]uit\n", style="dim")
        header_text.append("⏯️  ", style="dim")
        header_text.append("[SPACE] Pause/Resume ", style="yellow")
        header_text.append("[C]lear Stats ", style="cyan")
        header_text.append("[V]iew Logs (scrollable)", style="white")
    else:
        header_text.append("  | Press [?] for help", style="dim")
    
    if split_mode and len(split_panels) > 0:
        header_text.append(f"\n🔀 Split Mode ({len(split_panels)}/4): {' + '.join(split_panels)}", style="bold magenta")
    
    return Panel(header_text, border_style="cyan")

def create_protocol_breakdown(analyzer, expanded=False):
    """Create protocol distribution table"""
    title = "📊 Protocol Distribution" + (" [EXPANDED - Press 0 for Overview]" if expanded else "")
    table = Table(title=title, show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Protocol", style="cyan", width=15)
    table.add_column("Count", justify="right", style="green", width=12)
    table.add_column("Percentage", justify="right", width=12)
    table.add_column("Graph", overflow="fold")
    
    total = sum(analyzer.protocol_counts.values())
    if total == 0:
        table.add_row("No data yet", "-", "-", "")
        return Panel(table, border_style="magenta")
    
    # Show more protocols when expanded
    limit = 20 if expanded else 8
    for protocol, count in analyzer.protocol_counts.most_common(limit):
        percentage = (count / total) * 100
        bar_length = int((count / total) * (60 if expanded else 30))
        bar = "█" * bar_length
        table.add_row(
            protocol,
            f"{count:,}",
            f"{percentage:.1f}%",
            f"[cyan]{bar}[/cyan]"
        )
    
    return Panel(table, border_style="magenta")

def create_top_talkers(analyzer, expanded=False):
    """Create top talkers table"""
    title = "🔝 Top Talkers (by Traffic)" + (" [EXPANDED - Press 0 for Overview]" if expanded else "")
    table = Table(title=title, show_header=True, header_style="bold yellow", expand=True)
    table.add_column("Rank", style="dim", width=6)
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Packets", justify="right", style="green", width=10)
    table.add_column("Data", justify="right", style="magenta", width=10)
    table.add_column("Domain/Service", style="yellow", overflow="fold")
    
    if not analyzer.ip_byte_counts:
        table.add_row("", "No data yet", "-", "-", "")
        return Panel(table, border_style="yellow")
    
    # Get top IPs by bytes - show more when expanded
    limit = 30 if expanded else 10
    top_ips = analyzer.ip_byte_counts.most_common(limit)
    
    for idx, (ip, bytes_val) in enumerate(top_ips, 1):
        packets = analyzer.ip_packet_counts[ip]
        
        # Try to find associated domain
        domain = ""
        for pkt in reversed(analyzer.packets):
            if pkt.get('src_ip') == ip or pkt.get('dst_ip') == ip:
                if 'domain' in pkt:
                    domain = pkt['domain']
                    break
                elif pkt.get('protocol') in ['DNS']:
                    domain = "DNS Server"
                    break
        
        table.add_row(
            f"{idx}.",
            ip,
            f"{packets:,}",
            analyzer.format_bytes(bytes_val),
            domain if domain else "-"
        )
    
    return Panel(table, border_style="yellow")

def create_recent_activity(analyzer, expanded=False):
    """Create recent packets stream"""
    title = "📡 Recent Packets" + (" [EXPANDED - Press 0 for Overview]" if expanded else "")
    table = Table(title=title, show_header=True, header_style="bold green", expand=True)
    table.add_column("Time", style="dim", width=10)
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("→", width=2)
    table.add_column("Destination", style="magenta", no_wrap=True)
    table.add_column("Protocol", style="yellow", width=10)
    table.add_column("Info", style="green", overflow="fold")
    
    if not analyzer.recent_packets:
        table.add_row("", "Waiting for packets...", "", "", "", "")
        return Panel(table, border_style="green")
    
    # Show more packets when expanded
    limit = 30 if expanded else 10
    for pkt in list(analyzer.recent_packets)[-limit:]:
        timestamp = datetime.fromtimestamp(float(pkt['timestamp'])).strftime('%H:%M:%S')
        src = pkt.get('src_ip', '')
        dst = pkt.get('dst_ip', '')
        protocol = pkt.get('protocol', '')
        
        # Build info string
        info = ""
        if 'domain' in pkt:
            info = pkt['domain']
        elif 'dns_query' in pkt:
            info = f"Query: {pkt['dns_query']}"
        elif 'src_port' in pkt and 'dst_port' in pkt:
            info = f":{pkt['src_port']}→:{pkt['dst_port']}"
        
        table.add_row(timestamp, src, "→", dst, protocol, info)
    
    return Panel(table, border_style="green")

def create_security_alerts(analyzer):
    """Create security alerts panel"""
    table = Table(show_header=True, header_style="bold red")
    table.add_column("Time", style="dim", width=8)
    table.add_column("Type", style="red", width=15)
    table.add_column("Alert Message", style="yellow")
    
    if not analyzer.alerts:
        return Panel(
            Text("✅ No security alerts detected", style="green"),
            title="🔒 Security Alerts",
            border_style="red"
        )
    
    for alert in list(analyzer.alerts)[-5:]:
        table.add_row(
            alert['time'],
            alert['type'],
            alert['msg']
        )
    
    return Panel(table, title="🔒 Security Alerts", border_style="red")

def create_raw_logs(analyzer, expanded=False):
    """Create raw packet logs panel"""
    title = "📋 Raw Packet Logs" + (" [EXPANDED - Press 0 for Overview]" if expanded else "")
    table = Table(title=title, show_header=True, header_style="bold white", expand=True)
    table.add_column("Time", style="dim", width=12)
    table.add_column("Raw JSON Data", style="cyan", overflow="fold")
    
    if not analyzer.raw_logs:
        table.add_row("", "Waiting for packets...")
        return Panel(table, border_style="white")
    
    # Show more logs when expanded
    limit = 50 if expanded else 15
    for log in list(analyzer.raw_logs)[-limit:]:
        timestamp = datetime.fromtimestamp(log['time']).strftime('%H:%M:%S.%f')[:-3]
        
        # Pretty format the JSON
        try:
            parsed = json.loads(log['data'])
            formatted = json.dumps(parsed, indent=2)
            table.add_row(timestamp, formatted)
        except:
            table.add_row(timestamp, log['data'])
    
    return Panel(table, border_style="white")

def create_domains_dns(analyzer, expanded_domains=False, expanded_dns=False):
    """Create domains and DNS panel"""
    # Domains table
    domains_title = "🌐 Top Domains" + (" [EXPANDED]" if expanded_domains else "")
    domains_table = Table(show_header=True, header_style="bold blue", title=domains_title, expand=True)
    domains_table.add_column("Domain", style="cyan", overflow="fold")
    domains_table.add_column("Hits", justify="right", style="green", width=10)
    
    limit_domains = 20 if expanded_domains else 5
    if analyzer.domain_counts:
        for domain, count in analyzer.domain_counts.most_common(limit_domains):
            domains_table.add_row(domain, f"{count:,}")
    else:
        domains_table.add_row("No HTTPS traffic yet", "-")
    
    # DNS table
    dns_title = "🔎 DNS Queries" + (" [EXPANDED]" if expanded_dns else "")
    dns_table = Table(show_header=True, header_style="bold blue", title=dns_title, expand=True)
    dns_table.add_column("Query", style="magenta", overflow="fold")
    dns_table.add_column("Count", justify="right", style="green", width=10)
    
    limit_dns = 20 if expanded_dns else 5
    if analyzer.dns_queries:
        for query, count in analyzer.dns_queries.most_common(limit_dns):
            dns_table.add_row(query, f"{count:,}")
    else:
        dns_table.add_row("No DNS queries yet", "-")
    
    combined = Table.grid()
    combined.add_row(domains_table, dns_table)
    
    return Panel(combined, border_style="blue")

def create_layout():
    """Create dashboard layout"""
    layout = Layout()
    
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="content", ratio=1)
    )
    
    return layout

def create_overview_layout():
    """Create the normal multi-panel layout"""
    layout = Layout()
    
    layout.split_row(
        Layout(name="left"),
        Layout(name="right")
    )
    
    layout["left"].split_column(
        Layout(name="protocols", ratio=1),
        Layout(name="domains_dns", ratio=1)
    )
    
    layout["right"].split_column(
        Layout(name="top_talkers", ratio=1),
        Layout(name="recent", ratio=1)
    )
    
    return layout

def get_panel_content(panel_name, analyzer):
    """Get the content for a specific panel"""
    if panel_name == "protocols":
        return create_protocol_breakdown(analyzer, expanded=True)
    elif panel_name == "talkers":
        return create_top_talkers(analyzer, expanded=True)
    elif panel_name == "recent":
        return create_recent_activity(analyzer, expanded=True)
    elif panel_name == "domains":
        return create_domains_dns(analyzer, expanded_domains=True)
    elif panel_name == "dns":
        return create_domains_dns(analyzer, expanded_dns=True)
    elif panel_name == "alerts":
        return create_security_alerts(analyzer)
    elif panel_name == "logs":
        return create_raw_logs(analyzer, expanded=True)
    else:
        return Panel("Unknown panel", border_style="red")

def update_dashboard(layout, analyzer):
    """Update all dashboard panels based on current view"""
    global current_view, split_mode, split_panels
    
    layout["header"].update(create_header(analyzer))
    
    # Check split mode FIRST (takes priority)
    if split_mode and len(split_panels) >= 1:
        # Split screen mode (1-4 panels)
        split_content = Layout()
        
        if len(split_panels) == 1:
            # Single panel (fullscreen)
            split_content = get_panel_content(split_panels[0], analyzer)
        
        elif len(split_panels) == 2:
            # Two panels (vertical split)
            split_content.split_row(
                Layout(get_panel_content(split_panels[0], analyzer)),
                Layout(get_panel_content(split_panels[1], analyzer))
            )
        
        elif len(split_panels) == 3:
            # Three panels (vertical split, right side splits horizontally)
            right_side = Layout()
            right_side.split_column(
                Layout(get_panel_content(split_panels[1], analyzer)),
                Layout(get_panel_content(split_panels[2], analyzer))
            )
            split_content.split_row(
                Layout(get_panel_content(split_panels[0], analyzer)),
                right_side
            )
        
        elif len(split_panels) == 4:
            # Four panels (2x2 grid)
            left_side = Layout()
            left_side.split_column(
                Layout(get_panel_content(split_panels[0], analyzer)),
                Layout(get_panel_content(split_panels[2], analyzer))
            )
            right_side = Layout()
            right_side.split_column(
                Layout(get_panel_content(split_panels[1], analyzer)),
                Layout(get_panel_content(split_panels[3], analyzer))
            )
            split_content.split_row(left_side, right_side)
        
        layout["content"].update(split_content)
    
    elif current_view == "overview":
        content = create_overview_layout()
        content["protocols"].update(create_protocol_breakdown(analyzer))
        content["top_talkers"].update(create_top_talkers(analyzer))
        content["recent"].update(create_recent_activity(analyzer))
        content["domains_dns"].update(create_domains_dns(analyzer))
        
        # Create bottom layout with alerts
        full_content = Layout()
        full_content.split_column(
            Layout(content, ratio=1),
            Layout(create_security_alerts(analyzer), size=8)
        )
        layout["content"].update(full_content)
    
    elif current_view == "protocols":
        # Full screen protocols
        layout["content"].update(create_protocol_breakdown(analyzer, expanded=True))
    
    elif current_view == "talkers":
        # Full screen top talkers
        layout["content"].update(create_top_talkers(analyzer, expanded=True))
    
    elif current_view == "recent":
        # Full screen recent packets
        layout["content"].update(create_recent_activity(analyzer, expanded=True))
    
    elif current_view == "domains":
        # Full screen domains
        layout["content"].update(create_domains_dns(analyzer, expanded_domains=True))
    
    elif current_view == "dns":
        # Full screen DNS
        layout["content"].update(create_domains_dns(analyzer, expanded_dns=True))
    
    elif current_view == "alerts":
        # Full screen alerts
        layout["content"].update(create_security_alerts(analyzer))
    
    elif current_view == "logs":
        # Full screen raw logs
        layout["content"].update(create_raw_logs(analyzer, expanded=True))

def main():
    parser = argparse.ArgumentParser(description='Packet Sniffer Dashboard')
    parser.add_argument('--interface', '-i', default='wlp2s0', help='Network interface to capture')
    args = parser.parse_args()
    
    global current_view, split_mode, split_panels, help_mode, paused
    analyzer = PacketAnalyzer(interface=args.interface)
    layout = create_layout()
    
    # Panel name mapping
    panel_map = {
        '1': 'protocols', 'p': 'protocols', 'P': 'protocols',
        '2': 'talkers', 't': 'talkers', 'T': 'talkers',
        '3': 'domains', 'd': 'domains', 'D': 'domains',
        '4': 'dns', 'n': 'dns', 'N': 'dns',
        '5': 'recent', 'r': 'recent', 'R': 'recent',
        '6': 'alerts', 'a': 'alerts', 'A': 'alerts',
        '7': 'logs', 'l': 'logs', 'L': 'logs'
    }
    
    # Start capture engine
    try:
        console.print(f"[bold cyan]Starting packet capture on {args.interface}...[/bold cyan]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")
        time.sleep(1)
        
        # Run C++ engine as subprocess
        process = subprocess.Popen(
            ['sudo', './capture_engine'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Send interface selection (assuming wlp2s0 is interface 0)
        process.stdin.write('0\n')
        process.stdin.flush()
        
        # Skip the interface selection output
        for _ in range(10):
            line = process.stdout.readline()
            if "Capturing on device" in line:
                break
        
        # Start live dashboard
        with Live(layout, console=console, screen=True, refresh_per_second=4) as live:
            import sys
            import tty
            import termios
            
            # Set terminal to raw mode for immediate key capture
            old_settings = termios.tcgetattr(sys.stdin)
            try:
                tty.setcbreak(sys.stdin.fileno())
                
                while True:
                    # Check for keyboard input (non-blocking)
                    if select.select([sys.stdin], [], [], 0)[0]:
                        key = sys.stdin.read(1)
                        
                        # Handle key presses
                        if key == '0' or key.lower() == 'o':
                            current_view = "overview"
                            split_mode = False
                            split_panels = []
                        
                        elif key == 's' or key == 'S':
                            # Toggle split mode
                            split_mode = not split_mode
                            if not split_mode:
                                split_panels = []
                        
                        elif key in panel_map:
                            if split_mode and len(split_panels) < 4:
                                # Adding panels to split view (max 4)
                                panel_name = panel_map[key]
                                if panel_name not in split_panels:
                                    split_panels.append(panel_name)
                            else:
                                # Normal single panel view
                                current_view = panel_map[key]
                                split_mode = False
                                split_panels = []
                        
                        elif key == '?':
                            # Toggle help mode
                            help_mode = not help_mode
                        
                        elif key == ' ':
                            # Toggle pause
                            paused = not paused
                        
                        elif key == 'c' or key == 'C':
                            # Clear/reset statistics
                            analyzer.reset()
                        
                        elif key == 'v' or key == 'V':
                            # View logs in new terminal window (live updating)
                            import subprocess as sp
                            import os
                            
                            log_path = 'packet_sniffer.log'
                            
                            # Check if log file exists
                            if not os.path.exists(log_path):
                                continue  # Skip if no logs yet
                            
                            # Try different terminal emulators - dashboard keeps running!
                            terminals = [
                                ['gnome-terminal', '--', 'bash', '-c', f'tail -f {log_path}; exec bash'],
                                ['xterm', '-e', 'bash', '-c', f'tail -f {log_path}; exec bash'],
                                ['konsole', '-e', 'bash', '-c', f'tail -f {log_path}; exec bash'],
                                ['x-terminal-emulator', '-e', 'bash', '-c', f'tail -f {log_path}; exec bash'],
                            ]
                            
                            for term_cmd in terminals:
                                try:
                                    sp.Popen(term_cmd)
                                    break  # Success - new terminal opened
                                except (FileNotFoundError, OSError):
                                    continue  # Try next terminal emulator
                        
                        elif key.lower() == 'q':
                            raise KeyboardInterrupt
                    
                    # Read packet data
                    if select.select([process.stdout], [], [], 0)[0]:
                        line = process.stdout.readline()
                        if not line:
                            break
                        
                        # Only process packets if not paused
                        if line.strip().startswith('{') and not paused:
                            analyzer.add_packet(line.strip())
                    
                    # Update display
                    update_dashboard(layout, analyzer)
                    time.sleep(0.05)  # Small delay to prevent CPU spinning
                    
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
                
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Shutting down...[/bold yellow]")
        analyzer.log_file.close()
        process.terminate()
        process.wait()
        
        # Show final stats
        console.print(f"\n[bold green]Session Summary:[/bold green]")
        console.print(f"  Total Packets: {len(analyzer.packets):,}")
        console.print(f"  Runtime: {int(time.time() - analyzer.start_time)}s")
        console.print(f"  Protocols seen: {len(analyzer.protocol_counts)}")
        console.print(f"  Unique IPs: {len(analyzer.ip_packet_counts)}")
    
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
