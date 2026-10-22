from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
print("\n\n\n")
print(PROJECT_ROOT)
# --- data files ---
DASHBOARD_HTML = PROJECT_ROOT / "dashboard" / "dashboard.html"
print(DASHBOARD_HTML)
SCREENSHOT_DIR = PROJECT_ROOT / "_local" / "screenshot"
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
print(SCREENSHOT_DIR)
SCREENSHOT = SCREENSHOT_DIR / "v2_my_screenshot.png"
OUTPUT_IMG = SCREENSHOT_DIR / "v2_output_image.png"
print(OUTPUT_IMG)
print(SCREENSHOT)