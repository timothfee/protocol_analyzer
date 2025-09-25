#!/usr/bin/env python3
"""
Internet Protocol Security Analyzer
Analyzes protocols and provides risk rankings with overviews
"""

import json
import os
import time

class ProtocolAnalyzer:
    def __init__(self, db_file='protocol_database.json'):
        self.db_file = db_file
        self.protocol_db = self.load_database()
    
    def load_database(self):
        """Load protocol database from JSON file"""
        try:
            if os.path.exists(self.db_file):
                with open(self.db_file, 'r') as f:
                    return json.load(f)
            else:
                print(f"Database file '{self.db_file}' not found.")
                print("Please ensure protocol_database.json exists in the same directory.")
                return {}
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading database: {e}")
            return {}
    
    def save_database(self, db=None):
        """Save protocol database to JSON file"""
        if db is None:
            db = self.protocol_db
        
        try:
            with open(self.db_file, 'w') as f:
                json.dump(db, f, indent=2)
            print(f"Database saved to {self.db_file}")
        except IOError as e:
            print(f"Error saving database: {e}")
    
    def get_risk_color(self, risk_level):
        """Return ANSI color code for risk level"""
        colors = {
            'LOW': '\033[92m',      # Green
            'MEDIUM': '\033[93m',   # Yellow
            'HIGH': '\033[91m',     # Red
            'CRITICAL': '\033[95m'  # Magenta
        }
        return colors.get(risk_level, '\033[0m')
    
    def reset_color(self):
        """Return ANSI reset code"""
        return '\033[0m'
    
    def analyze_protocol(self, protocol):
        """Analyze a single protocol and return formatted information"""
        protocol = protocol.lower().strip()
        
        if protocol not in self.protocol_db:
            return f"\nProtocol '{protocol}' not found in database"
        
        info = self.protocol_db[protocol]
        color = self.get_risk_color(info['risk_level'])
        reset = self.reset_color()
        
        result = []
        result.append(f"\n{'='*60}")
        result.append(f"{info['name']} ({protocol.upper()})")
        result.append(f"{'='*60}")
        result.append(f"Category: {info['category']}")
        result.append(f"Port: {info['port']}")
        result.append(f"Risk Level: {color}{info['risk_level']}{reset}")
        result.append(f"\nDescription:")
        result.append(f"  {info['description']}")
        result.append(f"\nSecurity Risks:")
        for risk in info['risks']:
            result.append(f"  • {risk}")
        
        return '\n'.join(result)
    
    def get_risk_summary(self, protocols):
        """Generate a risk summary for all analyzed protocols"""
        risk_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        valid_protocols = []
        risky_protocols = []  # List of (protocol_name, risk_level)

        for protocol in protocols:
            protocol = protocol.lower().strip()
            if protocol in self.protocol_db:
                valid_protocols.append(protocol)
                risk_level = self.protocol_db[protocol]['risk_level']
                risk_counts[risk_level] += 1
                if risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']:
                    risky_protocols.append((protocol.upper(), risk_level))

        if not valid_protocols:
            return "No valid protocols found for summary."

        # Calculate total risky protocols
        critical_high_medium_total = risk_counts['CRITICAL'] + risk_counts['HIGH'] + risk_counts['MEDIUM']
        
        # Only show "POSSIBLE FINDINGS" section if there are risky protocols
        if critical_high_medium_total > 0:
            summary = ["\n" + "=" * 60, "POSSIBLE FINDINGS", "=" * 60]
            summary.append(f"Total Protocols Analyzed: {len(valid_protocols)}")
            summary.append("")

            for risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']:
                count = risk_counts[risk_level]
                if count > 0:
                    color = self.get_risk_color(risk_level)
                    reset = self.reset_color()
                    summary.append(f"{color}{risk_level}{reset}: {count} protocol(s)")

            summary.append(f"\nTotal Possible Findings: {critical_high_medium_total} protocol(s)")
            summary.append("Affected Protocols:")

            # Sort by risk severity: CRITICAL -> HIGH -> MEDIUM
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
            risky_protocols.sort(key=lambda x: severity_order.get(x[1], 3))

            for proto, level in risky_protocols:
                color = self.get_risk_color(level)
                reset = self.reset_color()
                summary.append(f"  • {proto} ({color}{level}{reset})")

            return '\n'.join(summary)
        else:
            # No risky protocols found
            summary = ["\n" + "=" * 60, "ANALYSIS SUMMARY", "=" * 60]
            summary.append(f"Total Protocols Analyzed: {len(valid_protocols)}")
            summary.append(f"No critical, high, or medium risk protocols detected")
            summary.append(f"All protocols are rated as LOW risk")
            return '\n'.join(summary)
    
    def reload_database(self):
        """Reload the database from the JSON file"""
        try:
            self.protocol_db = self.load_database()
            print(f"Database reloaded from {self.db_file}")
            print(f"Loaded {len(self.protocol_db)} protocols")
        except Exception as e:
            print(f"Error reloading database: {e}")
    
    def get_database_info(self):
        """Display information about the current database"""
        print(f"\nDatabase Information:")
        print(f"{'='*50}")
        print(f"Database file: {self.db_file}")
        print(f"Total protocols: {len(self.protocol_db)}")
        print(f"File exists: {'✅' if os.path.exists(self.db_file) else '❌'}")
        
        # Count by category and risk level
        categories = {}
        risk_levels = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        
        for protocol, info in self.protocol_db.items():
            category = info['category']
            categories[category] = categories.get(category, 0) + 1
            risk_levels[info['risk_level']] += 1
        
        print(f"\nBy Category:")
        for category, count in sorted(categories.items()):
            print(f"  {category}: {count}")
        
        print(f"\nBy Risk Level:")
        for risk, count in risk_levels.items():
            if count > 0:
                color = self.get_risk_color(risk)
                reset = self.reset_color()
                print(f"  {color}{risk}{reset}: {count}")
    
    def export_database(self, filename=None):
        """Export current database to a new JSON file"""
        if filename is None:
            filename = f"protocol_database_backup_{int(time.time())}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.protocol_db, f, indent=2)
            print(f"Database exported to {filename}")
        except IOError as e:
            print(f"Error exporting database: {e}")
    
    def add_protocol(self, protocol_name, protocol_info):
        """Add a new protocol to the database"""
        required_fields = ['name', 'description', 'port', 'risks', 'risk_level', 'category']
        
        for field in required_fields:
            if field not in protocol_info:
                raise ValueError(f"Missing required field: {field}")
        
        if protocol_info['risk_level'] not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            raise ValueError("Risk level must be: LOW, MEDIUM, HIGH, or CRITICAL")
        
        self.protocol_db[protocol_name.lower()] = protocol_info
        print(f"Added protocol: {protocol_name}")
    
    def list_protocols(self):
        """List all available protocols by category"""
        categories = {}
        for protocol, info in self.protocol_db.items():
            category = info['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(protocol.upper())
        
        print("\nAvailable Protocols by Category:")
        print("="*50)
        for category, protocols in sorted(categories.items()):
            print(f"\n{category}:")
            for protocol in sorted(protocols):
                risk = self.protocol_db[protocol.lower()]['risk_level']
                color = self.get_risk_color(risk)
                reset = self.reset_color()
                print(f"  • {protocol} ({color}{risk}{reset})")
    
    def search_protocols(self, search_term):
        """Search for protocols by name, description, or category"""
        search_term = search_term.lower()
        results = []
        
        for protocol, info in self.protocol_db.items():
            if (search_term in protocol.lower() or 
                search_term in info['name'].lower() or 
                search_term in info['description'].lower() or
                search_term in info['category'].lower()):
                results.append(protocol)
        
        if results:
            print(f"\nSearch results for '{search_term}':")
            for protocol in sorted(results):
                info = self.protocol_db[protocol]
                risk = info['risk_level']
                color = self.get_risk_color(risk)
                reset = self.reset_color()
                print(f"  • {protocol.upper()} - {info['name']} ({color}{risk}{reset})")
        else:
            print(f"No protocols found matching '{search_term}'")
    
    def analyze_from_file(self, filename):
        """Analyze protocols from a text file"""
        if not os.path.exists(filename):
            return f"File '{filename}' not found"
        
        try:
            with open(filename, 'r') as f:
                protocols = [line.strip() for line in f if line.strip()]
            
            if not protocols:
                return f"File '{filename}' is empty"
            
            print(f"Analyzing {len(protocols)} protocols from '{filename}':")
            print(", ".join(protocols))
            print()
            
            # Analyze each protocol
            for protocol in protocols:
                result = self.analyze_protocol(protocol)
                print(result)
            
            # Generate summary
            summary = self.get_risk_summary(protocols)
            print(summary)
            print("\n" + "=" * 60)
            
            return f"Analysis complete for {len(protocols)} protocols"
            
        except IOError as e:
            return f"Error reading file: {e}"

def main():
    analyzer = ProtocolAnalyzer()
    
    print("Internet Protocol Security Analyzer by Timothy Fee") 
    print("Can't expect to remember them all!")
    print("="*50)
    print(f"Database: {analyzer.db_file}")
    print(f"Protocols loaded: {len(analyzer.protocol_db)}")
    print("\nCommands:")
    print("  • Enter protocols: http,igmp,telnet,dhcp")
    print("  • 'file <filename>' - Analyze protocols from text file")
    print("  • 'list'           - Show all available protocols")
    print("  • 'search <term>'  - Search for protocols")
    print("  • 'info'           - Show database information")
    print("  • 'reload'         - Reload database from JSON file")
    print("  • 'save'           - Save current database to file")
    print("  • 'export [name]'  - Export database backup")
    print("  • 'add'            - Add new protocol")
    print("  • 'help'           - List your options again")
    print("  • 'exit'           - Exit program")
    
    while True:
        user_input = input("\n> ").strip()
        
        if user_input.lower() == 'exit':
            print("Goodbye!")
            break
        
        elif user_input.lower() == 'list':
            analyzer.list_protocols()
        
        elif user_input.lower() == 'info':
            analyzer.get_database_info()
        
        elif user_input.lower() == 'help':
            print("Internet Protocol Security Analyzer by Timothy Fee")
            print("="*50)
            print(f"Database: {analyzer.db_file}")
            print(f"Protocols loaded: {len(analyzer.protocol_db)}")
            print("\nCommands:")
            print("  • Enter protocols: http,igmp,telnet,dhcp")
            print("  • 'file <filename>' - Analyze protocols from text file")
            print("  • 'list' - Show all available protocols")
            print("  • 'search <term>' - Search for protocols")
            print("  • 'info' - Show database information")
            print("  • 'reload' - Reload database from JSON file")
            print("  • 'save' - Save current database to file")
            print("  • 'export [filename]' - Export database backup")
            print("  • 'add' - Add new protocol (interactive)")
            print("  • 'help' - List your options again")
            print("  • 'exit' - Exit program")
        
        elif user_input.lower() == 'reload':
            analyzer.reload_database()
        
        elif user_input.lower().startswith('search '):
            search_term = user_input[7:].strip()
            if search_term:
                analyzer.search_protocols(search_term)
            else:
                print("Please provide a search term: search <term>")
        
        elif user_input.lower() == 'save':
            analyzer.save_database()
        
        elif user_input.lower().startswith('export'):
            parts = user_input.split()
            filename = parts[1] if len(parts) > 1 else None
            analyzer.export_database(filename)
        
        elif user_input.lower() == 'add':
            try:
                print("\nAdding new protocol:")
                protocol_name = input("Protocol name: ").strip().lower()
                
                if protocol_name in analyzer.protocol_db:
                    print(f"⚠️  Protocol '{protocol_name}' already exists!")
                    overwrite = input("Overwrite? (y/N): ").strip().lower()
                    if overwrite != 'y':
                        print("Cancelled")
                        continue
                
                name = input("Full name: ").strip()
                description = input("Description: ").strip()
                port = input("Port (or 'N/A'): ").strip()
                category = input("Category: ").strip()
                
                print("Risk level (LOW/MEDIUM/HIGH/CRITICAL): ", end="")
                risk_level = input().strip().upper()
                
                if risk_level not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                    print("Invalid risk level")
                    continue
                
                risks = []
                print("Enter risks (press Enter on empty line when done):")
                while True:
                    risk = input("  Risk: ").strip()
                    if not risk:
                        break
                    risks.append(risk)
                
                if not risks:
                    print("At least one risk must be specified")
                    continue
                
                protocol_info = {
                    'name': name,
                    'description': description,
                    'port': port,
                    'risks': risks,
                    'risk_level': risk_level,
                    'category': category
                }
                
                analyzer.add_protocol(protocol_name, protocol_info)
                print("Use 'save' command to persist changes to file")
                
            except (ValueError, KeyboardInterrupt) as e:
                print(f"Error adding protocol: {e}")
        
        elif user_input.lower().startswith('file '):
            filename = user_input[5:].strip()
            if filename:
                result = analyzer.analyze_from_file(filename)
                print(result)
            else:
                print("Please provide a filename: file <filename>")
        
        elif not user_input:
            print("Please enter protocol names (comma-separated or one per line).")
            print("Press Enter on an empty line to finish multi-line input.")
            protocols = []

            while True:
                line = input("> ").strip()
                if line == "":
                    break
                if ',' in line:
                    # Allow comma-separated input in multi-line mode
                    protocols.extend([p.strip() for p in line.split(',') if p.strip()])
                else:
                    protocols.append(line)

            if not protocols:
                print("No protocols entered.")
                continue

            # Analyze each protocol
            for protocol in protocols:
                result = analyzer.analyze_protocol(protocol)
                print(result)

            # Generate summary
            summary = analyzer.get_risk_summary(protocols)
            print(summary)
            print("\n" + "=" * 60)
        
        else:
            # Fallback for single-line comma-separated input
            protocols = [p.strip() for p in user_input.split(',') if p.strip()]
            if not protocols:
                print("No valid protocols entered.")
                continue

            # Analyze each protocol
            for protocol in protocols:
                result = analyzer.analyze_protocol(protocol)
                print(result)

            # Generate summary
            summary = analyzer.get_risk_summary(protocols)
            print(summary)
            print("\n" + "=" * 60)

if __name__ == "__main__":
    main()
