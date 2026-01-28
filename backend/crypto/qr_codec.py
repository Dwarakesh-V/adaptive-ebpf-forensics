import qrcode
from PIL import Image
import json

def generate_qr(data: dict, output_path: str):
    payload = json.dumps(data)
    qr = qrcode.make(payload)
    qr.save(output_path)

def decode_qr(image_path: str) -> dict:
    from pyzbar.pyzbar import decode
    img = Image.open(image_path)
    decoded = decode(img)
    if not decoded:
        return {}
    return json.loads(decoded[0].data.decode())
