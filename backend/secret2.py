import base64

key = b'\xd6\xfa\xe3^!\xbf)\xdf\xa8\x91\xc0\x11\t\xd9\xbd\xb0\xcb!\x92\x85\xf6\xedt\x1e'
base64_key = base64.b64encode(key)
print(base64_key.decode())
