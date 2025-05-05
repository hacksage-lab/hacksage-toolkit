import argparse
from core.auth import Authentication
from core.config import ConfigManager
from modules.recon.domain_analyzer import DomainAnalyzer

def main():
    parser = argparse.ArgumentParser(description="SentinelX Ethical Hacking Framework")
    subparsers = parser.add_subparsers(dest="command")
    
    # Auth commands
    auth_parser = subparsers.add_parser('auth', help='Authentication operations')
    
    # Recon commands
    recon_parser = subparsers.add_parser('recon', help='Reconnaissance operations')
    recon_parser.add_argument('-d', '--domain', help='Domain to analyze')
    recon_parser.add_argument('--dns', action='store_true', help='Perform DNS lookup')
    recon_parser.add_argument('--whois', action='store_true', help='Perform WHOIS lookup')
    
    args = parser.parse_args()
    
    # Initialize configuration
    config = ConfigManager()
    
    if args.command == 'recon':
        if not args.domain:
            print("Error: Domain is required for reconnaissance")
            return
            
        analyzer = DomainAnalyzer(args.domain)
        
        if args.dns:
            print("\nDNS Records:")
            print(analyzer.get_dns_records())
            
        if args.whois:
            print("\nWHOIS Information:")
            print(analyzer.get_whois_info())
            
    else:
        # Default to authentication check
        auth = Authentication(config)
        if not auth.authenticate():
            print("Authentication failed. Exiting.")
            return
        
        print("Authentication successful. Launching SentinelX...")

if __name__ == "__main__":
    main()