import os
import json
import click
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from eth_hash.auto import keccak

KEY_FILE = "wallet_key.pem"

# --- HELPER FUNCTIONS ---

def load_private_key():
    if not os.path.exists(KEY_FILE):
        raise Exception("❌ No wallet exists. Run: python wallet_crypto.py generate")
    with open(KEY_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def save_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(KEY_FILE, "wb") as f:
        f.write(pem)

def get_public_key_bytes(private_key):
    # Lấy bytes dạng Uncompressed (0x04 + X + Y)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

def public_key_bytes_to_address(pub_key_bytes):
    """
    Tạo địa chỉ kiểu Ethereum từ Public Key bytes:
    1. Bỏ byte đầu tiên (prefix 0x04)
    2. Hash Keccak-256
    3. Lấy 20 bytes cuối
    """
    pub_no_prefix = pub_key_bytes[1:] 
    keccak_hash = keccak(pub_no_prefix)
    return "0x" + keccak_hash[-20:].hex()

def hex_to_public_key(pub_hex):
    """Chuyển chuỗi Hex Public Key ngược lại thành Object để Verify"""
    pub_bytes = bytes.fromhex(pub_hex)
    return serialization.load_der_public_key(
        # Lưu ý: cryptography thường load DER, nhưng để đơn giản ta load từ raw point
        # cần wrap lại theo chuẩn X9.62 hoặc dùng hàm load phù hợp. 
        # Để code đơn giản nhất, ta dùng EllipticCurvePublicKey.from_encoded_point
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_bytes)
    )

# --- CLI COMMANDS ---

@click.group()
def cli():
    """Wallet Tool using 'cryptography' lib"""
    pass

# 1️⃣ WALLET GENERATION
@cli.command()
def generate():
    """Generate private/public key & address"""
    # Tạo Private Key trên đường cong SECP256K1 (Chuẩn Bitcoin/Eth)
    private_key = ec.generate_private_key(ec.SECP256K1())
    save_private_key(private_key)

    pub_bytes = get_public_key_bytes(private_key)
    address = public_key_bytes_to_address(pub_bytes)

    click.echo("✅ Wallet generated!")
    click.echo(f"Address:    {address}")
    # In ra Public Key Hex để dùng cho verify sau này
    click.echo(f"Public Key: {pub_bytes.hex()}")


# 2️⃣ SIGN MESSAGE
@cli.command()
@click.argument("message")
def sign(message):
    """Sign a message."""
    try:
        private_key = load_private_key()

        # Hash message (SHA256) trước khi ký
        # Lưu ý: Blockchain thật dùng Keccak, nhưng cryptography lib dùng SHA256 chuẩn hơn
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )

        pub_bytes = get_public_key_bytes(private_key)
        address = public_key_bytes_to_address(pub_bytes)

        output = {
            "message": message,
            "address": address,
            "public_key": pub_bytes.hex(), # Cần cái này để verify
            "signature": signature.hex(),
        }

        click.echo(json.dumps(output, indent=4))
    except Exception as e:
        click.echo(f"Error: {e}")


# 3️⃣ VERIFY SIGNATURE
@cli.command()
@click.argument("message")
@click.argument("signature")
@click.argument("public_key_hex")
def verify(message, signature, public_key_hex):
    """
    Verify signature using PUBLIC KEY (Not Address).
    Vì 'cryptography' không hỗ trợ Recover Address từ Signature.
    """
    try:
        signature_bytes = bytes.fromhex(signature)
        
        # 1. Tái tạo Public Key Object từ chuỗi Hex đầu vào
        # (KHÔNG load từ file private key nữa -> Bảo mật chuẩn)
        pub_bytes = bytes.fromhex(public_key_hex)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_bytes)

        # 2. (Tùy chọn) Tính lại Address để đối chiếu xem đúng ví không
        derived_address = public_key_bytes_to_address(pub_bytes)
        click.echo(f"ℹ️  Signer Address: {derived_address}")

        # 3. Thực hiện Verify toán học
        public_key.verify(
            signature_bytes,
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        
        click.echo("✅ Signature Valid! (Chữ ký chuẩn)")
        
    except Exception as e:
        click.echo(f"❌ Invalid Signature or Key! Error: {e}")

if __name__ == "__main__":
    cli()