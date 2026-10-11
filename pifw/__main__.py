import sys, json
from . import Firewall
def main():
    a = sys.argv[1:]
    if a[:1] == ["serve"]:
        from .server import serve; return serve()
    if a[:1] == ["scan"] and len(a) > 1:
        p = a[1]; data = sys.stdin.read() if p == "-" else open(p, "rb").read()
        r = Firewall().scan(data, "user_message" if p == "-" else "auto", filename="" if p == "-" else p)
        print(json.dumps(r.to_dict(), indent=2)); return
    print("usage: python -m pifw serve | scan <file|->")
main()
