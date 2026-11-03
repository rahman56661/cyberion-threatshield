import glob
REPL = [("javascript:", "javascript[:]"), ("http://", "hxxp://"), ("https://", "hxxps://"),
        ("GetObject(", "GetObject[(]"), ("ActiveXObject", "ActiveX[Object]"),
        ("WScript.Shell", "WScript[.]Shell"), ("RunHTMLApplication", "RunHTML[App]"),
        ("scrobj.dll", "scrobj[.]dll")]

def fix(t):
    for a, b in REPL:
        t = t.replace(a, b)
    return t

def main():
    for p in glob.glob("results/evidence/*.csv") + ["results/iocs.json"]:
        t = open(p, encoding="utf-8").read()
        open(p, "w", encoding="utf-8").write(fix(t))
    p = "docs/03_rule_library.md"
    out = []
    for line in open(p, encoding="utf-8"):
        out.append(fix(line) if line.lstrip().startswith("*Evidence") else line)
    open(p, "w", encoding="utf-8").write("".join(out))
    print("evidence strings defanged")

if __name__ == "__main__":
    main()