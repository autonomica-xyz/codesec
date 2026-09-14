"""Detection probe dataset for the codesec vuln-toolbox.

Hand-curated, CWE-tagged Python snippets with a deliberate difficulty
gradient so small/large models separate (no ceiling effect). Every
vulnerable snippet is genuinely exploitable; every "safe" decoy is
genuinely safe (so flagging it is a real false positive).

  vuln=True  -> a real bug; model should say vulnerable + correct CWE
  vuln=False -> safe code that *looks* risky; model should say safe

Tiers (the discrimination signal):
  T1 blatant   - obvious sink, any competent model catches
  T2 medium    - incomplete/misplaced sanitization, framework nuance
  T3 subtle    - logic/timing/state, separates great from good
"""
import hashlib
import json

# Each: dict(id, tier, lang, vuln, cwe, cls, code, note)
CASES = [
# ============================== T1 — blatant ==============================
{"id":"t1_eval","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-94","cls":"code_injection","code":'''
@app.route("/calc")
def calc():
    return jsonify(eval(request.args["expr"]))
''',"note":"eval on raw user input"},
{"id":"t1_pickle","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-502","cls":"deserialization","code":'''
@app.route("/restore", methods=["POST"])
def restore():
    return pickle.loads(request.data)
''',"note":"pickle on raw body"},
{"id":"t1_shell","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-78","cls":"command_injection","code":'''
def ping(host):
    return os.system("ping -c 1 " + host)
''',"note":"shell=True concat"},
{"id":"t1_ssti","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-94","cls":"ssti","code":'''
@app.route("/preview")
def preview():
    return render_template_string(request.form["body"])
''',"note":"render_template_string on input"},
{"id":"t1_sqli","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-89","cls":"sql_injection","code":'''
def find(name):
    c.execute("SELECT * FROM users WHERE name = '%s'" % name)
''',"note":"string-formatted SQL"},
{"id":"t1_redirect","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-601","cls":"open_redirect","code":'''
@app.route("/go")
def go():
    return redirect(request.args.get("next"))
''',"note":"redirect to arbitrary next"},
{"id":"t1_traversal","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-22","cls":"path_traversal","code":'''
@app.route("/file")
def file():
    return open(os.path.join(UPLOADS, request.args["name"])).read()
''',"note":"join with raw name, no normalization"},
{"id":"t1_yaml","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-502","cls":"deserialization","code":'''
cfg = yaml.load(request.data, Loader=yaml.UnsafeLoader)
''',"note":"explicit unsafe loader permits arbitrary object construction"},
{"id":"t1_ssrf","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-918","cls":"ssrf","code":'''
def fetch(url):
    return urllib.request.urlopen(url).read()
''',"note":"server fetches arbitrary url"},
{"id":"t1_md5","tier":"T1","lang":"py","vuln":True,"cwe":"CWE-327","cls":"weak_crypto","code":'''
def hash_pw(pw): return hashlib.md5(pw.encode()).hexdigest()
''',"note":"md5 for passwords"},

# ============================== T2 — medium ==============================
{"id":"t2_ssrf_allowlist","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-918","cls":"ssrf","code":'''
def fetch(url):
    host = urlparse(url).hostname
    if host == "localhost":
        abort(403)
    return urlopen(url).read()
''',"note":"allowlist bypass: 127.0.0.1 / 0x7f000001 / 2130706433 / [::1]"},
{"id":"t2_orderby_sqli","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-89","cls":"sql_injection","code":'''
def list(sort):
    c.execute("SELECT * FROM notes ORDER BY %s" % sort)
''',"note":"ORDER BY identifier injection"},
{"id":"t2_basename_traversal","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-22","cls":"path_traversal","code":'''
def get(name):
    name = os.path.basename(name)
    name = urllib.parse.unquote(name)
    return open(BASE + "/" + name).read()
''',"note":"validation-before-decoding traversal"},
{"id":"t2_jwt_none","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-347","cls":"auth","code":'''
data = jwt.decode(token, options={"verify_signature": False})
''',"note":"signature verification disabled"},
{"id":"t2_redos","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-1333","cls":"redos","code":'''
PATT = re.compile(r"^(a+)+$")
def check(s): return bool(PATT.match(s))
''',"note":"catastrophic backtracking on user input"},
{"id":"t2_eval_sandbox","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-94","cls":"code_injection","code":'''
def calc(e): return eval(e, {"__builtins__": {}}, {})
''',"note":"sandboxed eval is escapable via type().__subclasses__()"},
{"id":"t2_markup_xss","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-79","cls":"xss","code":'''
return render_template("page.html", body=Markup(user_text))
''',"note":"Markup() / |safe bypasses autoescape"},
{"id":"t2_random_token","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-330","cls":"weak_crypto","code":'''
def token(): return "".join(random.choice(string.ascii_letters) for _ in range(16))
''',"note":"non-cryptographic RNG for security token"},
{"id":"t2_mass_assign","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-915","cls":"mass_assignment","code":'''
u = User.query.get(uid); 
for k,v in request.json.items(): setattr(u, k, v)
''',"note":"client controls every attribute incl. is_admin"},
{"id":"t2_xx_lang","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-611","cls":"xxe","code":'''
parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
root = etree.fromstring(request.data, parser)
''',"note":"lxml parser explicitly resolves attacker-controlled external entities"},
{"id":"t2_shell_missing_quote","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-78","cls":"command_injection","code":'''
def archive(name):
    os.system("tar czf out.tgz " + name)
''',"note":"one arg unquoted -> shell metachars"},
{"id":"t2_cookie_secure","tier":"T2","lang":"py","vuln":True,"cwe":"CWE-614","cls":"weak_crypto","code":'''
app.config.update(SESSION_COOKIE_SECURE=False)
''',"note":"session cookie over http"},

# ============================== T3 — subtle ==============================
{"id":"t3_toctou","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-367","cls":"race","code":'''
def serve(path):
    if os.path.exists(path) and allowed(path):
        return open(path).read()
''',"note":"check-then-use race (symlink swap)"},
{"id":"t3_hmac_timing","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-208","cls":"timing","code":'''
def check(sig): return sig == request.cookies["sig"]
''',"note":"non-constant-time string compare leaks token"},
{"id":"t3_authz_logic","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-863","cls":"authz","code":'''
def view(note_id):
    n = get_note(note_id)
    if n.public or n.owner_id == session.get("uid") or session.get("role") == "user":
        return n
''',"note":"boolean flaw: 'user' role sees everything"},
{"id":"t3_second_order","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-89","cls":"sql_injection","code":'''
def create(name): c.execute("INSERT INTO notes(name) VALUES (?)", (name,))
def search_admin(): 
    row = c.execute("SELECT name FROM notes WHERE id=1").fetchone()
    c.execute("SELECT * FROM notes WHERE name = '%s'" % row[0])
''',"note":"clean on input, concatenated elsewhere"},
{"id":"t3_jwt_alg_confusion","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-347","cls":"auth","code":'''
header = jwt.get_unverified_header(token)
if header["alg"] == "HS256":
    data = jwt.decode(token, RSA_PUBLIC_KEY_BODY, algorithms=["HS256"])
else:
    data = jwt.decode(token, RSA_PUBLIC_KEY_PEM, algorithms=["RS256"])
''',"note":"public key material is accepted as an HMAC secret for attacker-selected HS256"},
{"id":"t3_object_hook","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-502","cls":"deserialization","code":'''
def hook(d): return eval(d.get("__call__")) if "__call__" in d else d
obj = json.loads(request.data, object_hook=hook)
''',"note":"json object_hook that calls eval"},
{"id":"t3_int_overflow","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-190","cls":"logic","code":'''
def transfer(amount):
    requested = int(amount)
    charged = ctypes.c_int32(requested).value
    if requested > 0 and balance - charged >= 0:
        balance -= charged
''',"note":"explicit signed-32-bit wrap can turn a large positive debit into a credit"},
{"id":"t3_argument_injection","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-88","cls":"argument_injection","code":'''
def archive(files):
    subprocess.run(["tar", "cf", "out.tar", *files], check=True)
''',"note":"attacker-controlled tar options can use --checkpoint-action to execute a command"},
{"id":"t3_bcrypt_low","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-916","cls":"weak_crypto","code":'''
h = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=4))
''',"note":"work factor too low for a secret"},
{"id":"t3_cache_key","tier":"T3","lang":"py","vuln":True,"cwe":"CWE-284","cls":"logic","code":'''
def can_view(user, document_id):
    if document_id in ACL_CACHE:
        return ACL_CACHE[document_id]
    ACL_CACHE[document_id] = db_can_view(user, document_id)
    return ACL_CACHE[document_id]
''',"note":"authorization cache omits user identity, reusing another user's decision"},

# ============================ decoys — safe ============================
{"id":"d_param_sql","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
c.execute("SELECT * FROM users WHERE name = ?", (name,))
''',"note":"parameterized -> safe"},
{"id":"d_shell_list","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
subprocess.run(["ping","-c","1",host], check=True)
''',"note":"shell=False, argv list -> safe"},
{"id":"d_eval_hardcoded","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
def area(r): return eval("3.14159 * r * r", {"__builtins__":{}}, {"r": float(r)})
''',"note":"eval on fixed expr, r only a number -> safe"},
{"id":"d_render_autoescape","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
return render_template("page.html", body=user_text)
''',"note":"render_template autoescapes -> safe"},
{"id":"d_redirect_allowlist","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
if url not in ALLOWED_URLS: abort(403)
return redirect(url)
''',"note":"strict allowlist -> safe"},
{"id":"d_bcrypt","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
h = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12))
''',"note":"proper hashing -> safe"},
{"id":"d_secrets_token","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
t = secrets.token_urlsafe(32)
''',"note":"cryptographic RNG -> safe"},
{"id":"d_realpath_guard","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
p = os.path.realpath(os.path.join(BASE, name))
if not p.startswith(BASE + os.sep): abort(403)
return open(p).read()
''',"note":"normalize + prefix check -> safe traversal guard"},
{"id":"d_safe_yaml","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
cfg = yaml.safe_load(request.data)
''',"note":"safe_load -> safe"},
{"id":"d_compare_digest","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
ok = hmac.compare_digest(sig, expected)
''',"note":"constant-time compare -> safe"},
{"id":"d_ssrf_allowlist_proper","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
parsed = urlparse(url)
if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
    abort(403)
return requests.get(url, allow_redirects=False, timeout=3).content
''',"note":"strict trusted-host allowlist, HTTPS-only, redirects disabled"},
{"id":"d_jwt_verify","tier":"decoy","lang":"py","vuln":False,"cwe":None,"cls":"safe","code":'''
data = jwt.decode(token, PUB, algorithms=["RS256"])
''',"note":"single algorithm, verified -> safe"},
]


def dataset_sha256(cases: list[dict] = CASES) -> str:
    canonical = [
        {
            key: case.get(key)
            for key in ("id", "tier", "lang", "vuln", "cwe", "code")
        }
        for case in cases
    ]
    payload = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(payload).hexdigest()


# sanity + asserts ----------------------------------------------------------------
if __name__ == "__main__":
    import collections
    assert len({c["id"] for c in CASES}) == len(CASES), "duplicate ids"
    vuln = [c for c in CASES if c["vuln"]]; safe = [c for c in CASES if not c["vuln"]]
    for c in vuln: assert c["cwe"], f"{c['id']} vuln but no cwe"
    by_tier = collections.Counter(c["tier"] for c in CASES)
    print(f"{len(CASES)} cases  vuln={len(vuln)} safe={len(safe)}")
    print("by tier:", dict(by_tier))
    print(json.dumps([{"id":c["id"],"tier":c["tier"],"vuln":c["vuln"],"cwe":c["cwe"]} for c in CASES], indent=0)[:600])
