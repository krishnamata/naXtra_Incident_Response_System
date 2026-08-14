# app/utils/mfa_utils.py
import pyotp, qrcode, io, base64

def generate_totp_secret():
    """Generate a new TOTP secret for a user."""
    return pyotp.random_base32()

def get_totp_uri(secret, username, issuer="naXtra Pulse IR"):
    """Return the provisioning URI for QR generation."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)

def generate_qr_base64(uri):
    """Generate a base64-encoded PNG QR code for the TOTP URI."""
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def verify_otp(secret, otp):
    """Verify an OTP entered by the user."""
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)
