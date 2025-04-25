# toolkit/scripts/ip_geolocation.py
import requests

def get_ip_geolocation(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(url)
        data = response.json()
        if data['status'] == 'fail':
            return None
        return {
            'ip': data.get('query'),
            'city': data.get('city'),
            'region': data.get('regionName'),
            'country': data.get('country'),
            'lat': data.get('lat'),
            'lon': data.get('lon')
        }
    except Exception as e:
        return {'error': str(e)}
