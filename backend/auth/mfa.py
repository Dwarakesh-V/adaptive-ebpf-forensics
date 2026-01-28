import pyotp

def generate_otp():
    secret = "JBSWY3DPEHPK3PXP"
    totp = pyotp.TOTP(secret)
    return totp.now()
