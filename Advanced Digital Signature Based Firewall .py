# -*- coding: utf-8 -*-
"""
Created on Wed Nov  5 18:28:20 2025

@author: kmkho
"""

#!/usr/bin/env python3
"""
Advanced Digital Signature Based Firewall
A comprehensive firewall application with GUI, digital signatures, and packet filtering
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import socket
import struct
import time
import json
import os
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import ipaddress


class DigitalSignatureManager:
    """Manages RSA key pairs and digital signatures"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.trusted_keys = {}
        
    def generate_keypair(self):
        """Generate a new RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return True
    
    def sign_data(self, data):
        """Sign data with private key"""
        if not self.private_key:
            raise ValueError("No private key available")
        
        signature = self.private_key.sign(
            data.encode() if isinstance(data, str) else data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, data, signature, public_key=None):
        """Verify signature with public key"""
        key = public_key or self.public_key
        if not key:
            raise ValueError("No public key available")
        
        try:
            key.verify(
                signature,
                data.encode() if isinstance(data, str) else data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
    
    def export_public_key(self):
        """Export public key in PEM format"""
        if not self.public_key:
            return None
        
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()
    
    def export_private_key(self, password=None):
        """Export private key in PEM format"""
        if not self.private_key:
            return None
        
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        return pem.decode()
    
    def import_public_key(self, pem_data, name="Unknown"):
        """Import a public key"""
        try:
            public_key = serialization.load_pem_public_key(
                pem_data.encode(),
                backend=default_backend()
            )
            key_hash = hashlib.sha256(pem_data.encode()).hexdigest()[:16]
            self.trusted_keys[key_hash] = {
                'key': public_key,
                'name': name,
                'added': datetime.now().isoformat()
            }
            return key_hash
        except Exception as e:
            raise ValueError(f"Failed to import key: {e}")


class FirewallRule:
    """Represents a firewall rule"""
    
    def __init__(self, rule_id, action, protocol, src_ip, src_port, 
                 dst_ip, dst_port, description="", signature=None):
        self.rule_id = rule_id
        self.action = action  # ALLOW or BLOCK
        self.protocol = protocol  # TCP, UDP, ICMP, ALL
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.description = description
        self.signature = signature
        self.created = datetime.now().isoformat()
        self.hit_count = 0
    
    def matches(self, packet_info):
        """Check if packet matches this rule"""
        # Check protocol
        if self.protocol != "ALL" and self.protocol != packet_info.get('protocol', ''):
            return False
        
        # Check source IP
        if self.src_ip != "ANY":
            try:
                if not self._ip_matches(packet_info.get('src_ip'), self.src_ip):
                    return False
            except:
                return False
        
        # Check destination IP
        if self.dst_ip != "ANY":
            try:
                if not self._ip_matches(packet_info.get('dst_ip'), self.dst_ip):
                    return False
            except:
                return False
        
        # Check source port
        if self.src_port != "ANY":
            if str(packet_info.get('src_port', '')) != str(self.src_port):
                return False
        
        # Check destination port
        if self.dst_port != "ANY":
            if str(packet_info.get('dst_port', '')) != str(self.dst_port):
                return False
        
        return True
    
    def _ip_matches(self, ip_str, rule_ip):
        """Check if IP matches rule (supports CIDR)"""
        if '/' in rule_ip:
            network = ipaddress.ip_network(rule_ip, strict=False)
            return ipaddress.ip_address(ip_str) in network
        return ip_str == rule_ip
    
    def to_dict(self):
        """Convert rule to dictionary"""
        return {
            'rule_id': self.rule_id,
            'action': self.action,
            'protocol': self.protocol,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'description': self.description,
            'signature': self.signature.hex() if self.signature else None,
            'created': self.created,
            'hit_count': self.hit_count
        }


class PacketMonitor:
    """Monitor network packets"""
    
    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self.thread = None
        self.packet_count = 0
        
    def start(self):
        """Start monitoring packets"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop monitoring packets"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _monitor_loop(self):
        """Main monitoring loop - simulated for demonstration"""
        # In a real implementation, this would capture actual network packets
        # For this demo, we'll simulate packet generation
        
        import random
        protocols = ['TCP', 'UDP', 'ICMP']
        
        while self.running:
            try:
                # Simulate packet capture
                packet_info = {
                    'timestamp': datetime.now().isoformat(),
                    'protocol': random.choice(protocols),
                    'src_ip': f"192.168.1.{random.randint(1, 254)}",
                    'src_port': random.randint(1024, 65535),
                    'dst_ip': f"10.0.0.{random.randint(1, 254)}",
                    'dst_port': random.choice([80, 443, 22, 3389, 8080]),
                    'size': random.randint(64, 1500)
                }
                
                self.packet_count += 1
                self.callback(packet_info)
                
                time.sleep(0.5)  # Simulate packet arrival rate
                
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(1)


class AdvancedFirewallGUI:
    """Main GUI application for the firewall"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Digital Signature Based Firewall")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.signature_manager = DigitalSignatureManager()
        self.rules = []
        self.packet_monitor = PacketMonitor(self.on_packet_received)
        self.monitoring = False
        self.stats = {
            'total_packets': 0,
            'allowed_packets': 0,
            'blocked_packets': 0
        }
        
        # Generate initial keypair
        self.signature_manager.generate_keypair()
        
        self.setup_ui()
        self.load_default_rules()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_rules_tab()
        self.create_monitor_tab()
        self.create_signatures_tab()
        self.create_logs_tab()
        
        # Status bar
        self.status_bar = tk.Label(self.root, text="Firewall Ready", 
                                   bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Dashboard")
        
        # Title
        title = tk.Label(tab, text="Firewall Control Center", 
                        font=("Arial", 18, "bold"))
        title.pack(pady=10)
        
        # Control frame
        control_frame = ttk.LabelFrame(tab, text="Control Panel", padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Start/Stop buttons
        btn_frame = tk.Frame(control_frame)
        btn_frame.pack()
        
        self.btn_start = tk.Button(btn_frame, text="Start Firewall", 
                                   command=self.start_firewall, 
                                   bg="green", fg="white", 
                                   font=("Arial", 12, "bold"),
                                   width=15)
        self.btn_start.pack(side=tk.LEFT, padx=5)
        
        self.btn_stop = tk.Button(btn_frame, text="Stop Firewall", 
                                  command=self.stop_firewall, 
                                  bg="red", fg="white", 
                                  font=("Arial", 12, "bold"),
                                  width=15, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(tab, text="Statistics", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Stats labels
        self.lbl_total = tk.Label(stats_frame, text="Total Packets: 0", 
                                 font=("Arial", 14))
        self.lbl_total.pack(pady=5)
        
        self.lbl_allowed = tk.Label(stats_frame, text="Allowed: 0", 
                                   font=("Arial", 14), fg="green")
        self.lbl_allowed.pack(pady=5)
        
        self.lbl_blocked = tk.Label(stats_frame, text="Blocked: 0", 
                                   font=("Arial", 14), fg="red")
        self.lbl_blocked.pack(pady=5)
        
        self.lbl_rules = tk.Label(stats_frame, text=f"Active Rules: {len(self.rules)}", 
                                 font=("Arial", 14))
        self.lbl_rules.pack(pady=5)
    
    def create_rules_tab(self):
        """Create rules management tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Firewall Rules")
        
        # Toolbar
        toolbar = tk.Frame(tab)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(toolbar, text="Add Rule", command=self.add_rule, 
                 bg="green", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="Edit Rule", command=self.edit_rule, 
                 bg="blue", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="Delete Rule", command=self.delete_rule, 
                 bg="red", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="Sign Rule", command=self.sign_selected_rule, 
                 bg="purple", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="Export Rules", command=self.export_rules, 
                 bg="orange", fg="white").pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="Import Rules", command=self.import_rules, 
                 bg="brown", fg="white").pack(side=tk.LEFT, padx=2)
        
        # Rules list
        list_frame = tk.Frame(tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Scrollbars
        vsb = tk.Scrollbar(list_frame, orient="vertical")
        hsb = tk.Scrollbar(list_frame, orient="horizontal")
        
        # Treeview
        self.rules_tree = ttk.Treeview(list_frame, 
                                       columns=("ID", "Action", "Protocol", 
                                               "Source", "Destination", "Description", "Signed"),
                                       show="headings",
                                       yscrollcommand=vsb.set,
                                       xscrollcommand=hsb.set)
        
        vsb.config(command=self.rules_tree.yview)
        hsb.config(command=self.rules_tree.xview)
        
        # Column headings
        self.rules_tree.heading("ID", text="ID")
        self.rules_tree.heading("Action", text="Action")
        self.rules_tree.heading("Protocol", text="Protocol")
        self.rules_tree.heading("Source", text="Source")
        self.rules_tree.heading("Destination", text="Destination")
        self.rules_tree.heading("Description", text="Description")
        self.rules_tree.heading("Signed", text="Signed")
        
        # Column widths
        self.rules_tree.column("ID", width=50)
        self.rules_tree.column("Action", width=80)
        self.rules_tree.column("Protocol", width=80)
        self.rules_tree.column("Source", width=150)
        self.rules_tree.column("Destination", width=150)
        self.rules_tree.column("Description", width=200)
        self.rules_tree.column("Signed", width=60)
        
        # Pack widgets
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.rules_tree.pack(fill=tk.BOTH, expand=True)
    
    def create_monitor_tab(self):
        """Create packet monitor tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Packet Monitor")
        
        # Toolbar
        toolbar = tk.Frame(tab)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(toolbar, text="Clear", command=self.clear_monitor).pack(side=tk.LEFT, padx=2)
        tk.Label(toolbar, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        filter_combo = ttk.Combobox(toolbar, textvariable=self.filter_var, 
                                    values=["ALL", "ALLOWED", "BLOCKED"], state="readonly")
        filter_combo.set("ALL")
        filter_combo.pack(side=tk.LEFT, padx=2)
        
        # Monitor text
        self.monitor_text = scrolledtext.ScrolledText(tab, height=30, 
                                                      font=("Courier", 9))
        self.monitor_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags for coloring
        self.monitor_text.tag_config("allowed", foreground="green")
        self.monitor_text.tag_config("blocked", foreground="red")
        self.monitor_text.tag_config("header", foreground="blue", font=("Courier", 9, "bold"))
    
    def create_signatures_tab(self):
        """Create digital signatures tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Digital Signatures")
        
        # Key management frame
        key_frame = ttk.LabelFrame(tab, text="Key Management", padding=10)
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        
        btn_frame = tk.Frame(key_frame)
        btn_frame.pack()
        
        tk.Button(btn_frame, text="Generate New Keypair", 
                 command=self.generate_keypair).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Export Public Key", 
                 command=self.export_public_key).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Export Private Key", 
                 command=self.export_private_key).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Import Trusted Key", 
                 command=self.import_trusted_key).pack(side=tk.LEFT, padx=5)
        
        # Public key display
        pub_key_frame = ttk.LabelFrame(tab, text="Your Public Key", padding=10)
        pub_key_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.public_key_text = scrolledtext.ScrolledText(pub_key_frame, height=8, 
                                                         font=("Courier", 9))
        self.public_key_text.pack(fill=tk.BOTH, expand=True)
        self.update_public_key_display()
        
        # Trusted keys frame
        trusted_frame = ttk.LabelFrame(tab, text="Trusted Public Keys", padding=10)
        trusted_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.trusted_tree = ttk.Treeview(trusted_frame, 
                                        columns=("ID", "Name", "Added"),
                                        show="headings", height=6)
        self.trusted_tree.heading("ID", text="Key ID")
        self.trusted_tree.heading("Name", text="Name")
        self.trusted_tree.heading("Added", text="Added")
        self.trusted_tree.pack(fill=tk.BOTH, expand=True)
    
    def create_logs_tab(self):
        """Create logs tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Event Logs")
        
        # Toolbar
        toolbar = tk.Frame(tab)
        toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(toolbar, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=2)
        tk.Button(toolbar, text="Export Logs", command=self.export_logs).pack(side=tk.LEFT, padx=2)
        
        # Log text
        self.log_text = scrolledtext.ScrolledText(tab, height=30, font=("Courier", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_event("Firewall initialized successfully")
    
    def start_firewall(self):
        """Start the firewall"""
        self.monitoring = True
        self.packet_monitor.start()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status_bar.config(text="Firewall Active - Monitoring Traffic")
        self.log_event("Firewall started")
        messagebox.showinfo("Firewall", "Firewall started successfully!")
    
    def stop_firewall(self):
        """Stop the firewall"""
        self.monitoring = False
        self.packet_monitor.stop()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status_bar.config(text="Firewall Stopped")
        self.log_event("Firewall stopped")
        messagebox.showinfo("Firewall", "Firewall stopped")
    
    def on_packet_received(self, packet_info):
        """Handle received packet"""
        if not self.monitoring:
            return
        
        self.stats['total_packets'] += 1
        
        # Check against rules
        action = "ALLOW"  # Default action
        matched_rule = None
        
        for rule in self.rules:
            if rule.matches(packet_info):
                action = rule.action
                matched_rule = rule
                rule.hit_count += 1
                break
        
        # Update statistics
        if action == "ALLOW":
            self.stats['allowed_packets'] += 1
        else:
            self.stats['blocked_packets'] += 1
        
        # Update GUI
        self.root.after(0, self.update_dashboard)
        self.root.after(0, self.update_monitor, packet_info, action, matched_rule)
    
    def update_dashboard(self):
        """Update dashboard statistics"""
        self.lbl_total.config(text=f"Total Packets: {self.stats['total_packets']}")
        self.lbl_allowed.config(text=f"Allowed: {self.stats['allowed_packets']}")
        self.lbl_blocked.config(text=f"Blocked: {self.stats['blocked_packets']}")
    
    def update_monitor(self, packet_info, action, rule):
        """Update packet monitor display"""
        filter_val = self.filter_var.get()
        if filter_val != "ALL" and filter_val != action:
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rule_info = f"Rule #{rule.rule_id}" if rule else "Default"
        
        line = f"[{timestamp}] {action:6} | {packet_info['protocol']:4} | "
        line += f"{packet_info['src_ip']:15}:{packet_info['src_port']:5} -> "
        line += f"{packet_info['dst_ip']:15}:{packet_info['dst_port']:5} | "
        line += f"{rule_info}\n"
        
        tag = "allowed" if action == "ALLOW" else "blocked"
        self.monitor_text.insert(tk.END, line, tag)
        self.monitor_text.see(tk.END)
        
        # Limit to last 1000 lines
        if int(self.monitor_text.index('end-1c').split('.')[0]) > 1000:
            self.monitor_text.delete(1.0, 2.0)
    
    def add_rule(self):
        """Add a new firewall rule"""
        dialog = RuleDialog(self.root, "Add Rule")
        if dialog.result:
            rule_id = len(self.rules) + 1
            rule = FirewallRule(
                rule_id=rule_id,
                action=dialog.result['action'],
                protocol=dialog.result['protocol'],
                src_ip=dialog.result['src_ip'],
                src_port=dialog.result['src_port'],
                dst_ip=dialog.result['dst_ip'],
                dst_port=dialog.result['dst_port'],
                description=dialog.result['description']
            )
            self.rules.append(rule)
            self.refresh_rules_list()
            self.log_event(f"Rule #{rule_id} added: {rule.description}")
            messagebox.showinfo("Success", "Rule added successfully!")
    
    def edit_rule(self):
        """Edit selected rule"""
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to edit")
            return
        
        item = self.rules_tree.item(selection[0])
        rule_id = int(item['values'][0])
        rule = next((r for r in self.rules if r.rule_id == rule_id), None)
        
        if rule:
            dialog = RuleDialog(self.root, "Edit Rule", rule)
            if dialog.result:
                rule.action = dialog.result['action']
                rule.protocol = dialog.result['protocol']
                rule.src_ip = dialog.result['src_ip']
                rule.src_port = dialog.result['src_port']
                rule.dst_ip = dialog.result['dst_ip']
                rule.dst_port = dialog.result['dst_port']
                rule.description = dialog.result['description']
                self.refresh_rules_list()
                self.log_event(f"Rule #{rule_id} modified")
    
    def delete_rule(self):
        """Delete selected rule"""
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to delete")
            return
        
        if messagebox.askyesno("Confirm", "Delete selected rule?"):
            item = self.rules_tree.item(selection[0])
            rule_id = int(item['values'][0])
            self.rules = [r for r in self.rules if r.rule_id != rule_id]
            self.refresh_rules_list()
            self.log_event(f"Rule #{rule_id} deleted")
    
    def sign_selected_rule(self):
        """Sign the selected rule with digital signature"""
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to sign")
            return
        
        item = self.rules_tree.item(selection[0])
        rule_id = int(item['values'][0])
        rule = next((r for r in self.rules if r.rule_id == rule_id), None)
        
        if rule:
            try:
                # Create signature of rule data
                rule_data = f"{rule.action}|{rule.protocol}|{rule.src_ip}|{rule.src_port}|{rule.dst_ip}|{rule.dst_port}"
                signature = self.signature_manager.sign_data(rule_data)
                rule.signature = signature
                self.refresh_rules_list()
                self.log_event(f"Rule #{rule_id} signed with digital signature")
                messagebox.showinfo("Success", "Rule signed successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to sign rule: {e}")
    
    def refresh_rules_list(self):
        """Refresh the rules list display"""
        self.rules_tree.delete(*self.rules_tree.get_children())
        
        for rule in self.rules:
            signed = "✓" if rule.signature else "✗"
            self.rules_tree.insert("", tk.END, values=(
                rule.rule_id,
                rule.action,
                rule.protocol,
                f"{rule.src_ip}:{rule.src_port}",
                f"{rule.dst_ip}:{rule.dst_port}",
                rule.description,
                signed
            ))
        
        self.lbl_rules.config(text=f"Active Rules: {len(self.rules)}")
    
    def load_default_rules(self):
        """Load default firewall rules"""
        default_rules = [
            FirewallRule(1, "BLOCK", "TCP", "ANY", "ANY", "ANY", "22", "Block SSH from internet"),
            FirewallRule(2, "ALLOW", "TCP", "192.168.1.0/24", "ANY", "ANY", "80", "Allow HTTP from local network"),
            FirewallRule(3, "ALLOW", "TCP", "192.168.1.0/24", "ANY", "ANY", "443", "Allow HTTPS from local network"),
            FirewallRule(4, "BLOCK", "ALL", "0.0.0.0/0", "ANY", "ANY", "ANY", "Block all external traffic (default)")
        ]
        
        for rule in default_rules:
            self.rules.append(rule)
        
        self.refresh_rules_list()
        self.log_event(f"Loaded {len(default_rules)} default rules")
    
    def export_rules(self):
        """Export rules to JSON file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                rules_data = [rule.to_dict() for rule in self.rules]
                with open(filepath, 'w') as f:
                    json.dump(rules_data, f, indent=4)
                self.log_event(f"Exported {len(self.rules)} rules to {filepath}")
                messagebox.showinfo("Success", "Rules exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export rules: {e}")
    
    def import_rules(self):
        """Import rules from JSON file"""
        filepath = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, 'r') as f:
                    rules_data = json.load(f)
                
                imported_count = 0
                for data in rules_data:
                    rule = FirewallRule(
                        rule_id=len(self.rules) + 1,
                        action=data['action'],
                        protocol=data['protocol'],
                        src_ip=data['src_ip'],
                        src_port=data['src_port'],
                        dst_ip=data['dst_ip'],
                        dst_port=data['dst_port'],
                        description=data.get('description', '')
                    )
                    if data.get('signature'):
                        rule.signature = bytes.fromhex(data['signature'])
                    self.rules.append(rule)
                    imported_count += 1
                
                self.refresh_rules_list()
                self.log_event(f"Imported {imported_count} rules from {filepath}")
                messagebox.showinfo("Success", f"Imported {imported_count} rules!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import rules: {e}")
    
    def clear_monitor(self):
        """Clear packet monitor display"""
        self.monitor_text.delete(1.0, tk.END)
    
    def generate_keypair(self):
        """Generate new RSA keypair"""
        if messagebox.askyesno("Confirm", "Generate new keypair? This will replace your current keys."):
            self.signature_manager.generate_keypair()
            self.update_public_key_display()
            self.log_event("Generated new RSA keypair")
            messagebox.showinfo("Success", "New keypair generated!")
    
    def update_public_key_display(self):
        """Update public key display"""
        self.public_key_text.delete(1.0, tk.END)
        pub_key = self.signature_manager.export_public_key()
        if pub_key:
            self.public_key_text.insert(1.0, pub_key)
    
    def export_public_key(self):
        """Export public key to file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                pub_key = self.signature_manager.export_public_key()
                with open(filepath, 'w') as f:
                    f.write(pub_key)
                self.log_event(f"Exported public key to {filepath}")
                messagebox.showinfo("Success", "Public key exported!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export key: {e}")
    
    def export_private_key(self):
        """Export private key to file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pem",
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                priv_key = self.signature_manager.export_private_key()
                with open(filepath, 'w') as f:
                    f.write(priv_key)
                self.log_event(f"Exported private key to {filepath}")
                messagebox.showwarning("Security Warning", 
                                      "Private key exported! Keep this file secure!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export key: {e}")
    
    def import_trusted_key(self):
        """Import a trusted public key"""
        filepath = filedialog.askopenfilename(
            filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, 'r') as f:
                    pem_data = f.read()
                
                name = os.path.basename(filepath)
                key_id = self.signature_manager.import_public_key(pem_data, name)
                
                self.refresh_trusted_keys()
                self.log_event(f"Imported trusted key: {name} (ID: {key_id})")
                messagebox.showinfo("Success", f"Trusted key imported!\nKey ID: {key_id}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import key: {e}")
    
    def refresh_trusted_keys(self):
        """Refresh trusted keys display"""
        self.trusted_tree.delete(*self.trusted_tree.get_children())
        
        for key_id, key_data in self.signature_manager.trusted_keys.items():
            self.trusted_tree.insert("", tk.END, values=(
                key_id,
                key_data['name'],
                key_data['added'][:19]
            ))
    
    def log_event(self, message):
        """Log an event"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_line)
        self.log_text.see(tk.END)
    
    def clear_logs(self):
        """Clear event logs"""
        self.log_text.delete(1.0, tk.END)
    
    def export_logs(self):
        """Export logs to file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Logs exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {e}")


class RuleDialog:
    """Dialog for adding/editing firewall rules"""
    
    def __init__(self, parent, title, rule=None):
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("500x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Create form
        form_frame = ttk.Frame(self.dialog, padding=10)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        row = 0
        
        # Action
        tk.Label(form_frame, text="Action:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.action_var = tk.StringVar(value=rule.action if rule else "ALLOW")
        action_combo = ttk.Combobox(form_frame, textvariable=self.action_var, 
                                    values=["ALLOW", "BLOCK"], state="readonly")
        action_combo.grid(row=row, column=1, sticky=tk.EW, pady=5)
        row += 1
        
        # Protocol
        tk.Label(form_frame, text="Protocol:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.protocol_var = tk.StringVar(value=rule.protocol if rule else "ALL")
        protocol_combo = ttk.Combobox(form_frame, textvariable=self.protocol_var, 
                                      values=["ALL", "TCP", "UDP", "ICMP"], state="readonly")
        protocol_combo.grid(row=row, column=1, sticky=tk.EW, pady=5)
        row += 1
        
        # Source IP
        tk.Label(form_frame, text="Source IP:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.src_ip_var = tk.StringVar(value=rule.src_ip if rule else "ANY")
        tk.Entry(form_frame, textvariable=self.src_ip_var).grid(row=row, column=1, sticky=tk.EW, pady=5)
        row += 1
        
        # Source Port
        tk.Label(form_frame, text="Source Port:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.src_port_var = tk.StringVar(value=rule.src_port if rule else "ANY")
        tk.Entry(form_frame, textvariable=self.src_port_var).grid(row=row, column=1, sticky=tk.EW, pady=5)
        row += 1
        
        # Destination IP
        tk.Label(form_frame, text="Destination IP:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.dst_ip_var = tk.StringVar(value=rule.dst_ip if rule else "ANY")
        tk.Entry(form_frame, textvariable=self.dst_ip_var).grid(row=row, column=1, sticky=tk.EW, pady=5)
        row += 1
        
        # Destination Port
        tk.Label(form_frame, text="Destination Port:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.dst_port_var = tk.StringVar(value=rule.dst_port if rule else "ANY")
        tk.Entry(form_frame, textvariable=self.dst_port_var).grid(row=row, column=1, sticky=tk.EW, pady=5)
        row += 1
        
        # Description
        tk.Label(form_frame, text="Description:").grid(row=row, column=0, sticky=tk.W, pady=5)
        self.desc_var = tk.StringVar(value=rule.description if rule else "")
        tk.Entry(form_frame, textvariable=self.desc_var).grid(row=row, column=1, sticky=tk.EW, pady=5)
        row += 1
        
        form_frame.columnconfigure(1, weight=1)
        
        # Buttons
        btn_frame = tk.Frame(self.dialog)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(btn_frame, text="OK", command=self.ok, 
                 bg="green", fg="white", width=10).pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=self.cancel, 
                 width=10).pack(side=tk.RIGHT, padx=5)
        
        self.dialog.wait_window()
    
    def ok(self):
        """Handle OK button"""
        self.result = {
            'action': self.action_var.get(),
            'protocol': self.protocol_var.get(),
            'src_ip': self.src_ip_var.get(),
            'src_port': self.src_port_var.get(),
            'dst_ip': self.dst_ip_var.get(),
            'dst_port': self.dst_port_var.get(),
            'description': self.desc_var.get()
        }
        self.dialog.destroy()
    
    def cancel(self):
        """Handle Cancel button"""
        self.dialog.destroy()


def main():
    """Main entry point"""
    root = tk.Tk()
    app = AdvancedFirewallGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()