# generate_icons.py
from PIL import Image, ImageDraw, ImageFont
import os
OUT = "icons"
os.makedirs(OUT, exist_ok=True)

def make(letter, size, path, bg=(196,33,33)):
    img = Image.new("RGBA", (size,size), bg+(255,))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", int(size*0.6))
    except:
        font = ImageFont.load_default()
    try:
        bbox = draw.textbbox((0,0), letter, font=font)
        w,h = bbox[2]-bbox[0], bbox[3]-bbox[1]
    except:
        w,h = draw.textsize(letter, font=font)
    draw.text(((size-w)/2,(size-h)/2), letter, font=font, fill=(255,255,255,255))
    img.save(path)

make("K",16, os.path.join(OUT,"icon16.png"))
make("K",48, os.path.join(OUT,"icon48.png"))
make("K",128, os.path.join(OUT,"icon128.png"))
print("icons created in", OUT)