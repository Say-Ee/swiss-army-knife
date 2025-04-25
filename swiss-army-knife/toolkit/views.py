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
        'active_tool_id': None, # <<< Initialize active_tool_id

        # Hash Tool
        'submitted_hash_input': '',
        'hash_results': None,
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
        active_tool = request.POST.get('active_tool') # <<< GET THE ID OF THE SUBMITTED TOOL SECTION
        context['active_tool_id'] = active_tool # <<< PASS IT BACK TO THE TEMPLATE

        # --- Always repopulate submitted values to preserve form state ---
        # (Consider if you only want to repopulate the active tool's form)
        context['submitted_hash_input'] = request.POST.get('hash_input', '')
        context['submitted_base64_input'] = request.POST.get('base64_input', '')
        context['submitted_base64_action'] = request.POST.get('base64_action', 'encode')
        context['submitted_ip_geo_input'] = request.POST.get('ip_geo_address', '')
        context['submitted_port_scan_ip'] = request.POST.get('port_scan_ip', '')
        context['submitted_port_scan_ports'] = request.POST.get('port_scan_ports', '')

        try: # Wrap main processing in a try block for general errors

            # --- Handle Hash Action ---
            # Check both action and the active_tool to be certain
            if action == 'hash' and active_tool == 'hash-tool':
                input_text = context['submitted_hash_input']
                if input_text:
                    context['hash_results'] = {
                        'md5': hashlib.md5(input_text.encode()).hexdigest(),
                        'sha1': hashlib.sha1(input_text.encode()).hexdigest(),
                        'sha256': hashlib.sha256(input_text.encode()).hexdigest()
                    }
                    context['show_hash_results'] = True
                else:
                    context['error_message'] = "Please enter text to hash." # Error specific to this tool

            # --- Handle Base64 Action ---
            elif action == 'base64' and active_tool == 'base64-tool':
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
                            # Ensure decoding uses a safe method, like utf-8 ignore errors
                            context['base64_result'] = base64.b64decode(base_input).decode('utf-8', 'ignore')
                        context['show_base64_results'] = True
                    except Exception as e:
                        # Show the error within the results area for this tool
                        context['base64_result'] = f"Error processing Base64: {e}"
                        context['show_base64_results'] = True
                else:
                    context['error_message'] = "Please enter text for Base64."

            # --- Handle Geolocation Action ---
            elif action == 'geolocate' and active_tool == 'ip-geo-tool':
                ip_address = context['submitted_ip_geo_input']
                if ip_address:
                    if get_ip_geolocation:
                        try:
                            context['geo_results'] = get_ip_geolocation(ip_address)
                            # Let template handle display, including potential 'error' key inside geo_results
                            context['show_geo_results'] = True
                        except Exception as e:
                             # Show error if the script itself fails catastrophically
                             context['error_message'] = f"Geolocation script execution error: {e}"
                             context['show_geo_results'] = True # Still show the section
                             context['geo_results'] = {'error': f"Script execution error: {e}"} # Pass error detail
                    else:
                         context['error_message'] = "Geolocation script not available."
                else:
                    context['error_message'] = "Please enter an IP address for geolocation."

            # --- Handle Port Scan Action ---
            elif action == 'scan_ports' and active_tool == 'port-scan-tool':
                ip_address = context['submitted_port_scan_ip']
                ports_input = context['submitted_port_scan_ports']
                if not ip_address:
                     context['error_message'] = "Please enter an IP address or hostname for port scanning."
                elif not ports_input:
                     context['error_message'] = "Please enter ports to scan."
                else:
                    if scan_ports:
                        try:
                            # Validate ports more robustly
                            ports_list_str = [p.strip() for p in ports_input.split(',') if p.strip()]
                            ports = []
                            for p_str in ports_list_str:
                                port_num = int(p_str)
                                if 0 <= port_num <= 65535:
                                     ports.append(port_num)
                                else:
                                     raise ValueError(f"Port number {port_num} out of range (0-65535).")
                            if not ports:
                                 raise ValueError("No valid ports specified after parsing.")

                            # Consider adding a timeout to scan_ports if it doesn't have one
                            context['port_scan_results'] = scan_ports(ip_address, ports)
                            context['show_port_results'] = True
                        except ValueError as e:
                             context['error_message'] = f"Invalid port input: {e}"
                        except socket.gaierror:
                             context['error_message'] = f"Could not resolve hostname: {ip_address}"
                        except Exception as e:
                             context['error_message'] = f"Port scan error: {e}"
                             # Optionally show results area even on error to display the message there too
                             # context['show_port_results'] = True
                             # context['port_scan_results'] = None # Or an error indicator
                    else:
                        context['error_message'] = "Port scanner script not available."

            # --- Unknown action (optional, helps debugging) ---
            elif action:
               context['error_message'] = f"Unknown action '{action}' received for tool '{active_tool}'."

        except Exception as e:
             # Catch any unexpected errors during processing
             print(f"Unhandled error in toolkit view: {e}") # Log detailed error
             context['error_message'] = "An unexpected error occurred. Please try again."


    # No 'else' needed for GET, context is already initialized

    return render(request, 'toolkit/combined_toolkit.html', context)

