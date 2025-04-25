# toolkit/views.py
import hashlib
import base64
import socket # Ensure socket is imported if used directly or indirectly
from django.shortcuts import render
# Make sure these imports point correctly to your scripts
try:
    from .scripts.ip_geolocation import get_ip_geolocation
except ImportError:
    get_ip_geolocation = None # Handle if script doesn't exist
    print("Warning: Could not import get_ip_geolocation")

try:
    from .scripts.port_scanner import scan_ports
except ImportError:
    scan_ports = None # Handle if script doesn't exist
    print("Warning: Could not import scan_ports")

def combined_toolkit_view(request):
    # Initialize context with defaults for all tools
    context = {
        # General
        'error_message': None,
        # Hash Tool
        'submitted_hash_input': '',
        'hash_results': None, #{'md5': '', 'sha1': '', 'sha256': ''}
        'show_hash_results': False,
        # Base64 Tool
        'submitted_base64_input': '',
        'submitted_base64_action': 'encode',
        'base64_result': None,
        'show_base64_results': False,
        # IP Geolocation Tool
        'submitted_ip_geo_input': '',
        'geo_results': None,
        'show_geo_results': False,
        # Port Scanner Tool
        'submitted_port_scan_ip': '',
        'submitted_port_scan_ports': '',
        'port_scan_results': None, # List of open ports
        'show_port_results': False,
    }

    if request.method == 'POST':
        action = request.POST.get('action') # Identify which form was submitted

        # --- Always repopulate submitted values to preserve form state ---
        context['submitted_hash_input'] = request.POST.get('hash_input', '')
        context['submitted_base64_input'] = request.POST.get('base64_input', '')
        context['submitted_base64_action'] = request.POST.get('base64_action', 'encode')
        context['submitted_ip_geo_input'] = request.POST.get('ip_geo_address', '')
        context['submitted_port_scan_ip'] = request.POST.get('port_scan_ip', '')
        context['submitted_port_scan_ports'] = request.POST.get('port_scan_ports', '')

        # --- Handle Hash Action ---
        if action == 'hash':
            input_text = context['submitted_hash_input']
            if input_text:
                try:
                    context['hash_results'] = {
                        'md5': hashlib.md5(input_text.encode()).hexdigest(),
                        'sha1': hashlib.sha1(input_text.encode()).hexdigest(),
                        'sha256': hashlib.sha256(input_text.encode()).hexdigest()
                    }
                    context['show_hash_results'] = True
                except Exception as e:
                    context['error_message'] = f"Hashing error: {e}"
            else:
                context['error_message'] = "Please enter text to hash."

        # --- Handle Base64 Action ---
        elif action == 'base64':
            base_input = context['submitted_base64_input']
            base_action = context['submitted_base64_action']
            if base_input:
                try:
                    if base_action == 'encode':
                        context['base64_result'] = base64.b64encode(base_input.encode()).decode()
                    elif base_action == 'decode':
                        # Add padding if needed for decoding
                        missing_padding = len(base_input) % 4
                        if missing_padding:
                            base_input += '='* (4 - missing_padding)
                        context['base64_result'] = base64.b64decode(base_input).decode()
                    context['show_base64_results'] = True
                except Exception as e:
                    context['base64_result'] = f"Error: {e}"
                    context['show_base64_results'] = True # Show error message
                    context['error_message'] = f"Base64 {base_action} error: {e}" # Also show general error
            else:
                context['error_message'] = "Please enter text for Base64."

        # --- Handle Geolocation Action ---
        elif action == 'geolocate':
            ip_address = context['submitted_ip_geo_input']
            if ip_address:
                if get_ip_geolocation:
                    try:
                        context['geo_results'] = get_ip_geolocation(ip_address)
                        context['show_geo_results'] = True
                    except Exception as e:
                        context['error_message'] = f"Geolocation error: {e}"
                else:
                     context['error_message'] = "Geolocation script not available."
            else:
                context['error_message'] = "Please enter an IP address for geolocation."

        # --- Handle Port Scan Action ---
        elif action == 'scan_ports':
            ip_address = context['submitted_port_scan_ip']
            ports_input = context['submitted_port_scan_ports']
            if not ip_address:
                 context['error_message'] = "Please enter an IP address for port scanning."
            elif not ports_input:
                 context['error_message'] = "Please enter ports to scan."
            else:
                if scan_ports:
                    try:
                        ports = [int(port.strip()) for port in ports_input.split(',')]
                        context['port_scan_results'] = scan_ports(ip_address, ports)
                        context['show_port_results'] = True
                    except ValueError:
                         context['error_message'] = "Invalid port number(s). Use comma-separated integers."
                    except Exception as e:
                         context['error_message'] = f"Port scan error: {e}"
                else:
                    context['error_message'] = "Port scanner script not available."

        # --- Unknown action (optional) ---
        # elif action:
        #    context['error_message'] = f"Unknown action: {action}"


    return render(request, 'toolkit/combined_toolkit.html', context)

# Keep old views if needed, otherwise remove them
# def hash_base64_tool(request): ...
# def ip_geo_port_tool(request): ...