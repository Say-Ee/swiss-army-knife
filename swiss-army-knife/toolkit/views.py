import hashlib
import base64
from django.shortcuts import render

def hash_base64_tool(request):
    result = {}
    
    if request.method == 'POST':
        tool = request.POST.get('tool')

        if tool == 'hash':
            input_text = request.POST.get('hash_input')
            result['md5'] = hashlib.md5(input_text.encode()).hexdigest()
            result['sha1'] = hashlib.sha1(input_text.encode()).hexdigest()
            result['sha256'] = hashlib.sha256(input_text.encode()).hexdigest()

        elif tool == 'base64':
            base_input = request.POST.get('base_input')
            action = request.POST.get('base_action')
            try:
                if action == 'encode':
                    result['base64_result'] = base64.b64encode(base_input.encode()).decode()
                elif action == 'decode':
                    result['base64_result'] = base64.b64decode(base_input).decode()
            except Exception as e:
                result['base64_result'] = f"Error: {e}"

    return render(request, 'toolkit/hash_base64.html', {'result': result})
