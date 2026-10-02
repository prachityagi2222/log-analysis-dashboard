import os
from pathlib import Path
from PIL import Image, ImageDraw

def create_icons():
    icons_dir = Path("src-tauri") / "icons"
    icons_dir.mkdir(parents=True, exist_ok=True)
    
    # Create base 512x512 image with dark cybersecurity theme and shield logo
    size = 512
    img = Image.new("RGBA", (size, size), (10, 14, 23, 255))
    draw = ImageDraw.Draw(img)
    
    # Outer circle / rounded rectangle
    margin = 32
    draw.rounded_rectangle(
        [margin, margin, size - margin, size - margin],
        radius=80,
        fill=(17, 24, 39, 255),
        outline=(6, 182, 212, 255),
        width=12
    )
    
    # Shield shape points
    shield_pts = [
        (256, 110),
        (380, 160),
        (380, 270),
        (256, 400),
        (132, 270),
        (132, 160)
    ]
    draw.polygon(shield_pts, fill=(30, 41, 59, 255), outline=(59, 130, 246, 255))
    
    # Inner accent
    inner_pts = [
        (256, 150),
        (340, 185),
        (340, 260),
        (256, 355),
        (172, 260),
        (172, 185)
    ]
    draw.polygon(inner_pts, fill=(6, 182, 212, 200))
    
    # Center text "L"
    # Draw simple crossbars or letter L
    draw.rectangle([230, 210, 250, 310], fill=(255, 255, 255, 255))
    draw.rectangle([230, 290, 285, 310], fill=(255, 255, 255, 255))
    
    # Save standard sizes
    img.save(icons_dir / "icon.png", format="PNG")
    img.resize((32, 32), Image.Resampling.LANCZOS).save(icons_dir / "32x32.png", format="PNG")
    img.resize((128, 128), Image.Resampling.LANCZOS).save(icons_dir / "128x128.png", format="PNG")
    img.resize((256, 256), Image.Resampling.LANCZOS).save(icons_dir / "128x128@2x.png", format="PNG")
    
    # Save .ico with multi-resolution
    ico_sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img.save(icons_dir / "icon.ico", format="ICO", sizes=ico_sizes)
    
    # Save .icns dummy/copy
    img.save(icons_dir / "icon.icns", format="PNG")
    
    print("Icons successfully generated in src-tauri/icons!")

if __name__ == "__main__":
    create_icons()
