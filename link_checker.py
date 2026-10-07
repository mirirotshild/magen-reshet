import os
import re
import time
import base64
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template

# הגדרת מפתח ה-API של VirusTotal
API_KEY = os.getenv("749a1d92d57de12b18aefed8bcce755ba1e7ad5c6ff6e9b5591fbbe3a9dfb278E")

# מילות מפתח נפוצות להפעלת לחץ והונאות
URGENCY_KEYWORDS = [
    "דחוף",
    "מיידי",
    "חסימה",
    "הושעה",
    "עיקול",
    "עדכון פרטים",
    "אשראי",
    "סיסמה",
    "קנס",
    "דואר ישראל",
    "דואר",
    "חבילה",
    "החשבון נחסם"
]

# דומיינים רשמיים של גופים מוכרים בישראל (לזיהוי התחזות)
OFFICIAL_ENTITIES = {
    "דואר ישראל": ["israelpost.co.il"],
    "דואר": ["israelpost.co.il"],
    "ביטוח לאומי": ["btl.gov.il"],
    "בנק הפועלים": ["bankhapoalim.co.il"],
    "בנק לאומי": ["leumi.co.il"],
    "בנק דיסקונט": ["discountbank.co.il"],
    "מזרחי טפחות": ["mizrahi-tefahot.co.il"],
    "כביש 6": ["kvish6.co.il"],
    "ישראכרט": ["isracard.co.il"],
    "כאל": ["cal-online.co.il"],
    "מקס": ["max.co.il"],
    "חברת החשמל": ["iec.co.il"],
}

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

def extract_links(text):
    return re.findall(r"(https?://[^\s]+)", text)

def check_domain_spoofing(text, link):
    """בדיקה האם הטקסט מתחזה לגוף רשמי אך הקישור מוביל לדומיין זר"""
    parsed = urlparse(link)
    domain = (parsed.netloc or parsed.path).lower()
    if ":" in domain:
        domain = domain.split(":")[0]
    
    for entity, valid_domains in OFFICIAL_ENTITIES.items():
        if entity in text:
            is_valid = any(domain == vd or domain.endswith("." + vd) for vd in valid_domains)
            if not is_valid:
                return f"🚨 התחזות חמורה: ההודעה מזכירה את '{entity}', אך הקישור מוביל לאתר זר ({domain}) במקום לאתר הרשמי!"
    return None

def check_url_safety(target_url):
    clean_url = target_url.strip(".,;:()")
    url_id = base64.urlsafe_b64encode(clean_url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": API_KEY}

    res = requests.get(endpoint, headers=headers)
    if res.status_code == 404:
        requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": clean_url},
        )
        time.sleep(10)
        res = requests.get(endpoint, headers=headers)

    if res.status_code != 200:
        return "שגיאה בבדיקת הקישור מול מאגר האבטחה"

    stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    threats = stats.get("malicious", 0) + stats.get("suspicious", 0)
    if threats > 0:
        return f"🚨 סכנה! {threats} מנועי אבטחה זיהו את האתר כזדוני!"
    return "🟢 הקישור נקי ומאומת במאגרים"

def analyze_text(text):
    links = extract_links(text)
    keywords = [k for k in URGENCY_KEYWORDS if k in text]
    report = []

    if keywords:
        report.append(f"⚠️ זוהו מילות לחץ חשודות: {', '.join(keywords)}")

    if not links:
        report.append("לא זוהה קישור בהודעה.")
    else:
        for link in links:
            # בדיקת התחזות לדומיין רשמי (עוקף Zero-Day)
            spoof_alert = check_domain_spoofing(text, link)
            if spoof_alert:
                report.append(spoof_alert)

            # בדיקה מול מאגר VirusTotal
            report.append(f"בודק קישור: {link}\nתוצאה: {check_url_safety(link)}")

    return "\n".join(report)

@app.route("/analyze", methods=["POST"])
@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    incoming_text = data.get("message", "")

    if not incoming_text:
        return jsonify({"error": "לא התקבל טקסט לבדיקה"}), 400

    result = analyze_text(incoming_text)
    
    is_danger = "זדוני" in result or "חשוד" in result or "מתחזה" in result or "עוקץ" in result
    alert_type = "danger" if is_danger else "safe"
    alert_msg = "המערכת מזהה חשד ממשי להונאה!" if is_danger else "לא זוהו ממצאים חריגים."

    return jsonify({
        "reply": result,
        "analysis": result,
        "alert": alert_msg,
        "alert_type": alert_type
    })

if __name__ == "__main__":
    print("...שרת הסריקה פועל וממתין להודעות")
    app.run(port=5000)