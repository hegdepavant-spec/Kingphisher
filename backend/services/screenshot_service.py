from playwright.sync_api import sync_playwright
import os
import time


def capture_screenshot(url: str, save_path="screenshots/temp/page.png"):
    """
    Capture webpage screenshot safely using headless browser
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        try:
            page.goto(url, timeout=10000)
            time.sleep(2)  # allow page to render
            page.screenshot(path=save_path, full_page=True)
        finally:
            browser.close()

    return save_path
