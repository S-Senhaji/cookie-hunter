#!/usr/bin/env python3
"""
REDHOOD CookieHunter - Advanced HTTP Cookie Security Analysis Tool
Developer: @0xRedHood (https://github.com/0xRedHood)
Contact: amirpedddii@gmail.com
"""

import argparse
import sys
import json
from typing import Dict, List, Optional
from urllib.parse import urlparse
from datetime import datetime
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint


class CookieHunter:
    def __init__(self):
        self.console = Console()
        
    def parse_cookie_string(self, cookie_string: str) -> Dict[str, str]:
        """Parse a Set-Cookie header string into a dictionary"""
        cookie_dict = {}
        parts = cookie_string.split(';')
        
        # First part is the cookie name=value
        if '=' in parts[0]:
            name, value = parts[0].split('=', 1)
            cookie_dict['name'] = name.strip()
            cookie_dict['value'] = value.strip()
        
        # Parse other attributes
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                attr_name, attr_value = part.split('=', 1)
                cookie_dict[attr_name.strip().lower()] = attr_value.strip()
            else:
                cookie_dict[part.lower()] = True
                
        return cookie_dict
    
    def analyze_cookie_security(self, cookie_name: str, cookie_dict: Dict[str, str], is_https: bool = True) -> List[Dict[str, str]]:
        """Analyze cookie security and return warnings with severity levels"""
        warnings = []
        
        # Check HttpOnly flag
        if 'httponly' not in cookie_dict:
            warnings.append({
                'severity': 'warning',
                'message': f"⚠️ Warning: Cookie {cookie_name} lacks HttpOnly flag",
                'type': 'missing_httponly',
                'remediation': 'Add HttpOnly flag to prevent XSS attacks'
            })
        
        # Check Secure flag (different severity for HTTPS vs HTTP)
        if 'secure' not in cookie_dict:
            if is_https:
                warnings.append({
                    'severity': 'critical',
                    'message': f"🔥 Critical: Cookie {cookie_name} lacks Secure flag on HTTPS",
                    'type': 'missing_secure_https',
                    'remediation': 'Add Secure flag to prevent cookie interception'
                })
            else:
                warnings.append({
                    'severity': 'warning',
                    'message': f"⚠️ Warning: Cookie {cookie_name} lacks Secure flag",
                    'type': 'missing_secure',
                    'remediation': 'Consider adding Secure flag for better security'
                })
        
        # Check SameSite attribute
        samesite = cookie_dict.get('samesite')
        if samesite is None:
            samesite = ''
        samesite = str(samesite).lower()
        
        if not samesite:
            warnings.append({
                'severity': 'warning',
                'message': f"⚠️ Warning: Cookie {cookie_name} lacks SameSite attribute",
                'type': 'missing_samesite',
                'remediation': 'Add SameSite=Strict or SameSite=Lax to prevent CSRF'
            })
        elif samesite not in ['strict', 'lax', 'none']:
            warnings.append({
                'severity': 'error',
                'message': f"❌ Error: Cookie {cookie_name} has invalid SameSite value ({samesite})",
                'type': 'invalid_samesite',
                'remediation': 'Use valid SameSite values: Strict, Lax, or None'
            })
        
        # Check Expires/Max-Age
        expires = cookie_dict.get('expires')
        max_age = cookie_dict.get('max-age')
        
        if max_age:
            try:
                max_age_seconds = int(max_age)
                if max_age_seconds > 86400 * 30:  # More than 30 days
                    warnings.append({
                        'severity': 'warning',
                        'message': f"⚠️ Warning: Cookie {cookie_name} has long expiration time ({max_age_seconds} seconds)",
                        'type': 'long_expiration',
                        'remediation': 'Consider shorter expiration times for better security'
                    })
                elif max_age_seconds < 0:
                    warnings.append({
                        'severity': 'error',
                        'message': f"❌ Error: Cookie {cookie_name} has negative Max-Age value",
                        'type': 'negative_max_age',
                        'remediation': 'Max-Age must be a positive number'
                    })
                elif max_age_seconds == 0:
                    warnings.append({
                        'severity': 'warning',
                        'message': f"⚠️ Warning: Cookie {cookie_name} has Max-Age=0 (session cookie)",
                        'type': 'session_cookie',
                        'remediation': 'This is a session cookie that will be deleted when browser closes'
                    })
            except ValueError:
                warnings.append({
                    'severity': 'error',
                    'message': f"❌ Error: Cookie {cookie_name} has invalid Max-Age value",
                    'type': 'invalid_max_age',
                    'remediation': 'Use valid numeric value for Max-Age'
                })
        
        # Check Expires date format
        if expires:
            try:
                from datetime import datetime
                # Try to parse the expires date
                parsed_date = datetime.strptime(expires, '%a, %d %b %Y %H:%M:%S GMT')
                now = datetime.now()
                if parsed_date < now:
                    warnings.append({
                        'severity': 'warning',
                        'message': f"⚠️ Warning: Cookie {cookie_name} has expired date",
                        'type': 'expired_cookie',
                        'remediation': 'Cookie will be ignored by browsers'
                    })
            except ValueError:
                warnings.append({
                    'severity': 'warning',
                    'message': f"⚠️ Warning: Cookie {cookie_name} has invalid Expires date format",
                    'type': 'invalid_expires',
                    'remediation': 'Use RFC 1123 date format: Mon, 02 Jan 2006 15:04:05 GMT'
                })
        
        # Check Path attribute
        path = cookie_dict.get('path', '/')
        if path == '/' and cookie_name.lower() in ['session', 'auth', 'token', 'id']:
            warnings.append({
                'severity': 'warning',
                'message': f"⚠️ Warning: Cookie {cookie_name} has overly broad path (/)",
                'type': 'broad_path',
                'remediation': 'Consider restricting path to specific endpoints'
            })
        
        # Check __Host- and __Secure- prefixes
        if cookie_name.startswith('__Host-'):
            if not cookie_dict.get('secure'):
                warnings.append({
                    'severity': 'error',
                    'message': f"❌ Error: Cookie {cookie_name} uses __Host- prefix but lacks Secure flag",
                    'type': 'host_prefix_secure',
                    'remediation': '__Host- cookies must have Secure flag'
                })
            if path != '/':
                warnings.append({
                    'severity': 'error',
                    'message': f"❌ Error: Cookie {cookie_name} uses __Host- prefix but path is not /",
                    'type': 'host_prefix_path',
                    'remediation': '__Host- cookies must have path=/'
                })
            if cookie_dict.get('domain'):
                warnings.append({
                    'severity': 'error',
                    'message': f"❌ Error: Cookie {cookie_name} uses __Host- prefix but has domain attribute",
                    'type': 'host_prefix_domain',
                    'remediation': '__Host- cookies must not have domain attribute'
                })
        
        if cookie_name.startswith('__Secure-'):
            if not cookie_dict.get('secure'):
                warnings.append({
                    'severity': 'error',
                    'message': f"❌ Error: Cookie {cookie_name} uses __Secure- prefix but lacks Secure flag",
                    'type': 'secure_prefix_secure',
                    'remediation': '__Secure- cookies must have Secure flag'
                })
        
        return warnings
    
    def send_request(self, url: str, method: str = "GET", headers: Dict[str, str] = None, data: Dict = None) -> requests.Response:
        """Send HTTP request to the URL"""
        try:
            if method.upper() == "POST":
                response = requests.post(url, headers=headers, json=data, timeout=10)
            else:
                response = requests.get(url, headers=headers, timeout=10)
            return response
        except requests.exceptions.RequestException as e:
            self.console.print(f"[red]Error sending request: {e}[/red]")
            sys.exit(1)
    
    def analyze_cookies(self, url: str, method: str = "GET", custom_headers: List[str] = None, 
                       data: Dict = None, output_file: str = None, json_output: bool = False):
        """Main method to analyze cookies from a URL"""
        
        # Parse custom headers
        headers = {}
        if custom_headers:
            for header in custom_headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Check if URL is HTTPS
        is_https = url.lower().startswith('https://')
        
        # Send request
        self.console.print(f"[blue]Sending {method} request to: {url}[/blue]")
        response = self.send_request(url, method, headers, data)
        
        # Check if response is successful
        if response.status_code != 200:
            self.console.print(f"[yellow]Warning: Status code {response.status_code}[/yellow]")
        
        # Get cookies from response (both Set-Cookie headers and response.cookies)
        cookies = response.cookies
        set_cookie_headers = []
        
        # Handle multiple Set-Cookie headers
        for header_name, header_value in response.headers.items():
            if header_name.lower() == 'set-cookie':
                set_cookie_headers.append(header_value)
        
        # Also check response.cookies (requests library parsed cookies)
        parsed_cookies = []
        for cookie in cookies:
            cookie_dict = {
                'name': cookie.name,
                'value': cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                'samesite': getattr(cookie, 'SameSite', None)
            }
            parsed_cookies.append(cookie_dict)
        
        if not set_cookie_headers and not parsed_cookies:
            self.console.print("[yellow]No cookies found in response[/yellow]")
            return
        
        # Create results table
        table = Table(title="Cookie Security Analysis Results")
        table.add_column("Cookie Name", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("HttpOnly", style="blue")
        table.add_column("Secure", style="blue")
        table.add_column("SameSite", style="blue")
        table.add_column("Path", style="blue")
        table.add_column("Expires", style="blue")
        table.add_column("Warnings", style="red")
        
        all_warnings = []
        all_cookies = []
        
        # Analyze cookies from Set-Cookie headers
        for cookie_header in set_cookie_headers:
            cookie_dict = self.parse_cookie_string(cookie_header)
            cookie_name = cookie_dict.get('name', 'Unknown')
            
            # Check security flags
            httponly = "✅" if 'httponly' in cookie_dict else "❌"
            secure = "✅" if 'secure' in cookie_dict else "❌"
            samesite = cookie_dict.get('samesite', 'None').title()
            path = cookie_dict.get('path', '/')
            expires = cookie_dict.get('expires', '') or cookie_dict.get('max-age', '')
            
            # Get warnings with severity
            warnings = self.analyze_cookie_security(cookie_name, cookie_dict, is_https)
            all_warnings.extend(warnings)
            
            # Store cookie info for JSON output
            all_cookies.append({
                'name': cookie_name,
                'value': cookie_dict.get('value', ''),
                'httponly': 'httponly' in cookie_dict,
                'secure': 'secure' in cookie_dict,
                'samesite': cookie_dict.get('samesite', 'None'),
                'path': path,
                'expires': expires,
                'warnings': warnings
            })
            
            warning_text = "\n".join([w['message'] for w in warnings]) if warnings else "No warnings"
            
            table.add_row(
                cookie_name,
                cookie_dict.get('value', '')[:20] + "..." if len(cookie_dict.get('value', '')) > 20 else cookie_dict.get('value', ''),
                httponly,
                secure,
                samesite,
                path,
                expires[:20] + "..." if len(expires) > 20 else expires,
                warning_text
            )
        
        # Analyze cookies from response.cookies
        for cookie_dict in parsed_cookies:
            cookie_name = cookie_dict['name']
            
            # Check security flags
            httponly = "✅" if cookie_dict['httponly'] else "❌"
            secure = "✅" if cookie_dict['secure'] else "❌"
            samesite = cookie_dict.get('samesite', 'None')
            path = cookie_dict.get('path', '/')
            expires = cookie_dict.get('expires', '')
            
            # Get warnings with severity
            warnings = self.analyze_cookie_security(cookie_name, cookie_dict, is_https)
            all_warnings.extend(warnings)
            
            # Store cookie info for JSON output
            all_cookies.append({
                'name': cookie_name,
                'value': cookie_dict['value'],
                'httponly': cookie_dict['httponly'],
                'secure': cookie_dict['secure'],
                'samesite': samesite,
                'path': path,
                'expires': expires,
                'warnings': warnings
            })
            
            warning_text = "\n".join([w['message'] for w in warnings]) if warnings else "No warnings"
            
            table.add_row(
                cookie_name,
                cookie_dict['value'][:20] + "..." if len(cookie_dict['value']) > 20 else cookie_dict['value'],
                httponly,
                secure,
                samesite,
                path,
                expires[:20] + "..." if len(expires) > 20 else expires,
                warning_text
            )
        
        # Display results
        self.console.print(table)
        
        # Display summary with severity
        if all_warnings:
            critical_warnings = [w for w in all_warnings if w['severity'] == 'critical']
            error_warnings = [w for w in all_warnings if w['severity'] == 'error']
            warning_warnings = [w for w in all_warnings if w['severity'] == 'warning']
            
            warning_text = []
            if critical_warnings:
                warning_text.append(f"🔥 Critical: {len(critical_warnings)} issues")
            if error_warnings:
                warning_text.append(f"❌ Error: {len(error_warnings)} issues")
            if warning_warnings:
                warning_text.append(f"⚠️ Warning: {len(warning_warnings)} issues")
            
            warning_panel = Panel(
                "\n".join([w['message'] for w in all_warnings]),
                title="Security Warnings",
                border_style="red"
            )
            self.console.print(warning_panel)
        else:
            self.console.print("[green]✅ All cookies are secure[/green]")
        
        # Save to file if requested
        if output_file:
            if json_output:
                self.save_results_to_json(url, all_cookies, all_warnings, output_file)
            else:
                self.save_results_to_file(url, table, all_warnings, output_file)
    
    def save_results_to_file(self, url: str, table: Table, warnings: List[Dict], filename: str):
        """Save analysis results to a file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"Cookie analysis results for: {url}\n")
                f.write("=" * 50 + "\n\n")
                
                # Save table as text
                f.write(str(table))
                f.write("\n\n")
                
                # Save warnings with severity
                if warnings:
                    f.write("Security Warnings:\n")
                    f.write("-" * 20 + "\n")
                    for warning in warnings:
                        f.write(f"{warning['message']}\n")
                else:
                    f.write("✅ All cookies are secure\n")
                    
            self.console.print(f"[green]Results saved to file {filename}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error saving file: {e}[/red]")
    
    def save_results_to_json(self, url: str, cookies: List[Dict], warnings: List[Dict], filename: str):
        """Save analysis results to JSON file"""
        try:
            result = {
                'url': url,
                'timestamp': str(datetime.now()),
                'cookies': cookies,
                'warnings': warnings,
                'summary': {
                    'total_cookies': len(cookies),
                    'total_warnings': len(warnings),
                    'critical_warnings': len([w for w in warnings if w['severity'] == 'critical']),
                    'error_warnings': len([w for w in warnings if w['severity'] == 'error']),
                    'warning_warnings': len([w for w in warnings if w['severity'] == 'warning'])
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
                    
            self.console.print(f"[green]Results saved to JSON file {filename}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error saving JSON file: {e}[/red]")


def main():
    parser = argparse.ArgumentParser(
        description="REDHOOD CookieHunter - Advanced HTTP Cookie Security Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cookie_hunter.py https://example.com
  python cookie_hunter.py https://example.com --method POST --data '{"key": "value"}'
  python cookie_hunter.py https://example.com --header "User-Agent: CookieHunter/1.0"
  python cookie_hunter.py https://example.com --output results.txt
  python cookie_hunter.py https://example.com --output results.json --json
        """
    )
    
    parser.add_argument("url", help="URL to analyze cookies from")
    parser.add_argument(
        "--method", "-m",
        default="GET",
        choices=["GET", "POST"],
        help="HTTP method to use (default: GET)"
    )
    parser.add_argument(
        "--data", "-d",
        help="JSON data for POST requests"
    )
    parser.add_argument(
        "--header", "-H",
        action="append",
        help="Custom header (example: --header 'User-Agent: CookieHunter')"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file to save results"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Save output in JSON format"
    )
    
    args = parser.parse_args()
    
    # Validate URL
    try:
        parsed_url = urlparse(args.url)
        if not parsed_url.scheme:
            args.url = "https://" + args.url
    except Exception:
        print("Error: Invalid URL")
        sys.exit(1)
    
    # Parse JSON data for POST requests
    data = None
    if args.data:
        try:
            data = json.loads(args.data)
        except json.JSONDecodeError:
            print("Error: Invalid JSON data")
            sys.exit(1)
    
    # Run analysis
    hunter = CookieHunter()
    hunter.analyze_cookies(
        args.url, 
        args.method, 
        args.header, 
        data, 
        args.output, 
        args.json
    )


if __name__ == "__main__":
    main() 