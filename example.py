from totp import totp
import time



password_key = "54HOIOBV4OFSKQNN37BI5JDPNHZB6A3E"






while True:
    code = totp(time.time(),password_key,30,6)
    print('code : ',code)
    time.sleep(30)

