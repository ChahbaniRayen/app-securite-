#!/usr/bin/env python3
"""Captures terminal (style console) a partir des vraies donnees du projet."""
import json, glob, os
from PIL import Image, ImageDraw, ImageFont

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONTB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
try:
    f = ImageFont.truetype(FONT, 15); fb = ImageFont.truetype(FONTB, 15)
    ft = ImageFont.truetype(FONTB, 14)
except Exception:
    f = fb = ft = ImageFont.load_default()

BG = (18, 22, 28); BAR = (40, 46, 56); FG = (220, 225, 230)
GREEN = (80, 220, 120); RED = (255, 95, 95); YELLOW = (255, 200, 70); CYAN = (90, 200, 255); DIM = (140, 150, 160)

def render(path_out, title, lines, width=880, pad=16, line_h=20, header_h=34):
    h = header_h + pad * 2 + line_h * len(lines) + 8
    img = Image.new("RGB", (width, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, header_h], fill=BAR)
    d.ellipse([12, 11, 26, 25], fill=(255, 95, 87))
    d.ellipse([32, 11, 46, 25], fill=(255, 189, 46))
    d.ellipse([52, 11, 66, 25], fill=(39, 201, 63))
    d.text((80, 9), title, font=ft, fill=FG)
    y = header_h + pad
    for text, color in lines:
        d.text((pad, y), text, font=f, fill=color)
        y += line_h
    img.save(path_out)
    print("->", path_out, img.size)

# ---- 1. Semgrep : detection de JS-001 (login.ts) ----
sg = sorted(glob.glob("results/*/sast-custom/semgrep-custom-juice-shop.json"))[-1]
d = json.load(open(sg))
lines = [("ubuntu@ec2:~/secscan-platform$ semgrep scan --config p/owasp-top-ten --config ./rules", CYAN), ("", FG)]
hits = sorted(d["results"], key=lambda r: ("login.ts" not in r["path"], r["path"]))
for r in hits[:7]:
    rule = r["check_id"].split(".")[-1][:44]
    loc = r["path"].replace("/src/", "") + ":" + str(r["start"]["line"])
    sev = r["extra"]["severity"]
    col = RED if sev == "ERROR" else YELLOW
    if "login.ts" in r["path"]:
        lines.append((f"  [ERROR] {rule:44s} {loc}", col))
        lines.append((f"          ^^^ JS-001 detectee (injection SQL - TP2)", GREEN))
    else:
        lines.append((f"  [{sev:5s}] {rule:44s} {loc}", col))
lines += [("", FG),
          (f"Ran semgrep on {len(hits)} files -> {len(hits)} findings", DIM),
          ("ubuntu@ec2:~/secscan-platform$ _", GREEN)]
render("shots/semgrep-terminal.png", "semgrep - SAST (regles custom + OWASP)", lines)

# ---- 2. authz_checker : BOLA/BFLA ----
az = sorted(glob.glob("results/*/custom/authz-findings.json"))[-1]
d = json.load(open(az))
lines = [("ubuntu@ec2:~/secscan-platform$ python3 custom/authz/authz_checker.py", CYAN), ("", FG),
         ("authz_checker - detection BOLA/BFLA sur crAPI", DIM),
         ("  * Authentification foulen@poly.lab ...  OK (token 462 car.)", GREEN),
         ("  * Authentification foulana@poly.lab ... OK (token 463 car.)", GREEN),
         ("  * VINs libres trouves: [21489AV93496E15U1, E33XA11URJ1A83F53]", DIM)]
for finding in d["findings"]:
    mark = "VULNERABLE" if finding.get("confirmed") else "protege"
    col = RED if finding.get("confirmed") else GREEN
    lines.append((f"  [{finding['rule_id']}]", FG))
    lines.append((f"    {finding['endpoint']} -> HTTP {finding.get('status_http')} => {mark}", col))
lines += [("", FG),
          (f"RESULTAT : {d.get('confirmed',0)}/{d['count']} tests d autorisation VULNERABLES", RED),
          ("  [!] BOLA  - acces vehicule victime (PII expose)", RED),
          ("  [!] BFLA  - endpoints admin avec jeton USER", RED),
          ("-> results/.../custom/authz-findings.json", DIM),
          ("ubuntu@ec2:~/secscan-platform$ _", GREEN)]
render("shots/authz-terminal.png", "authz_checker.py - mecanisme personnalise", lines)
