import secrets
import string
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import pyotp
import qrcode
import io
import base64


def generate_secure_token(length=32):
    """Generate cryptographically secure random token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_verification_token():
    """Generate verification token"""
    return generate_secure_token(64)


def generate_password_reset_token():
    """Generate password reset token"""
    return generate_secure_token(64)


def send_verification_email(user, token, token_type='email'):
    """Send verification email to user"""
    if token_type == 'email':
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
        subject = 'Verify Your Email Address'
        message = f"""
        Hello {user.username},
        
        Please verify your email address by clicking the link below:
        {verification_url}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, please ignore this email.
        """
    else:
        subject = 'Account Verification'
        message = f"Your verification code is: {token}"
    
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def send_password_reset_email(user, token):
    """Send password reset email"""
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    subject = 'Password Reset Request'
    message = f"""
    Hello {user.username},
    
    You requested a password reset. Click the link below to reset your password:
    {reset_url}
    
    This link will expire in 1 hour.
    
    If you didn't request this, please ignore this email.
    """
    
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def send_verification_sms(phone_number, code):
    """Send verification SMS (placeholder - integrate with Twilio or similar)"""
    # TODO: Integrate with SMS provider (Twilio, AWS SNS, etc.)
    print(f"SMS verification code for {phone_number}: {code}")
    return True


def generate_mfa_secret():
    """Generate TOTP secret for MFA"""
    return pyotp.random_base32()


def generate_mfa_qr_code(user, secret, issuer_name="Enterprise System"):
    """Generate QR code for MFA setup"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email or user.username,
        issuer_name=issuer_name
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{img_base64}"


def verify_totp_code(secret, code):
    """Verify TOTP code"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Allow 1 step window for clock skew


def validate_password_complexity(password):
    """Validate password meets complexity requirements"""
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    special_chars = string.punctuation
    if not any(c in special_chars for c in password):
        errors.append("Password must contain at least one special character")
    
    return errors


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

