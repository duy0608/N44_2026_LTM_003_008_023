#!/usr/bin/env python3
"""
benchmark.py - Khung script benchmark cho do an Firewall (nguoi C - Kiem thu).

DASHBOARD MOI (FastAPI): cac lenh "-api" goi API cua backend de do chinh he thong that:
  api-rule-time | load-api | accuracy-setup-api | cleanup-api | api-status
  (dung --api http://IP:CONG, mac dinh http://127.0.0.1:8000; chay duoc ngay tren FIREWALL VM)
  Luu y: backend phai TAT dry-run, neu khong rule khong vao nftables va so lieu vo nghia.

Chay tren 2 VM:
  FIREWALL VM (can root, co nftables):  rule-time | load | serve | accuracy-setup | cleanup
  CLIENT VM:                            latency | throughput | accuracy | nmap

Chi dung thu vien chuan. Them --dry-run de xem lenh ma khong chay.
Ket qua ghi vao results/*.csv

Quy trinh do hieu nang (moi cau hinh: none / rules / set  x  N = 10,100,1000):
  [FW]     sudo python3 benchmark.py load --mode rules --n 100
  [CLIENT] python3 benchmark.py latency    --target 192.168.56.10 --port 5201 --label rules-100
  [CLIENT] python3 benchmark.py throughput --target 192.168.56.10 --label rules-100
  [FW]     sudo python3 benchmark.py cleanup
  (cach qua Dashboard: thay "load --mode rules" bang "load-api --mode rules --n 100", cleanup bang "cleanup-api")
"""
import argparse
import csv
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

TABLE = "bench"          # bang nft rieng, khong dung chung voi bang cua Dashboard
CHAIN = "input"
RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "docs", "data")
API = "http://127.0.0.1:8000"
PREFIX = "bench-"   # ten rule do script tao, de don dep khong dung rule that cua nhom
DRY = False


# ---------------------------------------------------------------- helpers
def run(cmd, stdin=None, check=True):
    """Chay lenh, tra ve (stdout, thoi_gian_giay)."""
    if DRY:
        print("[dry-run]", " ".join(cmd) if isinstance(cmd, list) else cmd)
        return "", 0.0
    t0 = time.perf_counter()
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True)
    dt = time.perf_counter() - t0
    if check and p.returncode != 0:
        sys.exit(f"Loi: {' '.join(cmd)}\n{p.stderr}")
    return p.stdout, dt


def save_csv(name, header, rows):
    if DRY:
        return
    os.makedirs(RESULTS, exist_ok=True)
    path = os.path.join(RESULTS, name)
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(header)
        w.writerows(rows)
    print(f"-> da ghi {os.path.normpath(path)}")


def fake_ip(i):
    """IP gia 10.99.x.y, khong trung IP client/firewall -> rule khong bao gio khop
    (do worst case: goi tin phai duyet het N rule)."""
    return f"10.99.{(i // 250) % 250}.{i % 250 + 1}"


def reset_table():
    run(["nft", "delete", "table", "inet", TABLE], check=False)
    run(["nft", "add", "table", "inet", TABLE])
    run(["nft", "add", "chain", "inet", TABLE, CHAIN,
         "{ type filter hook input priority 0 ; policy accept ; }"])


# ---------------------------------------------------------------- FIREWALL side
def cmd_rule_time(a):
    """Do thoi gian them N rule bang lenh nft thu cong (BASELINE) - 3 cach:
       single: nft add rule tung cai | batch: nft -f 1 lan | set: them N phan tu vao set."""
    rows = []
    for n in a.ns:
        for rep in range(a.repeat):
            # 1) tung rule rieng le
            reset_table()
            t0 = time.perf_counter()
            for i in range(n):
                run(["nft", "add", "rule", "inet", TABLE, CHAIN,
                     "ip", "saddr", fake_ip(i), "tcp", "dport", "9999", "drop"])
            t_single = time.perf_counter() - t0
            # 2) batch 1 lan
            reset_table()
            lines = "\n".join(
                f"add rule inet {TABLE} {CHAIN} ip saddr {fake_ip(i)} tcp dport 9999 drop"
                for i in range(n))
            _, t_batch = run(["nft", "-f", "-"], stdin=lines)
            # 3) set
            reset_table()
            run(["nft", "add", "set", "inet", TABLE, "blk", "{ type ipv4_addr ; }"])
            run(["nft", "add", "rule", "inet", TABLE, CHAIN, "ip saddr @blk drop"])
            elems = ", ".join(fake_ip(i) for i in range(n))
            _, t_set = run(["nft", "add", "element", "inet", TABLE, "blk", "{ " + elems + " }"])
            rows.append([n, rep, round(t_single, 6), round(t_batch, 6), round(t_set, 6)])
            print(f"N={n:5d} rep={rep}  single={t_single:.3f}s  batch={t_batch:.4f}s  set={t_set:.4f}s")
    run(["nft", "delete", "table", "inet", TABLE], check=False)
    save_csv("rule_time_baseline.csv", ["n", "rep", "single_s", "batch_s", "set_s"], rows)
    # TODO (khi A xong API v0.1 - CN 15/11): them cot "dashboard_api_s" bang cach goi
    #   POST /api/rules N lan (urllib.request) va do thoi gian.


def cmd_load(a):
    """Nap cau hinh de do latency/throughput: none | rules | set."""
    reset_table()
    if a.mode == "rules":
        lines = "\n".join(
            f"add rule inet {TABLE} {CHAIN} ip saddr {fake_ip(i)} tcp dport {a.port} drop"
            for i in range(a.n))
        run(["nft", "-f", "-"], stdin=lines)
    elif a.mode == "set":
        run(["nft", "add", "set", "inet", TABLE, "blk", "{ type ipv4_addr ; }"])
        run(["nft", "add", "rule", "inet", TABLE, CHAIN, "ip saddr @blk", "drop"])
        elems = ", ".join(fake_ip(i) for i in range(a.n))
        run(["nft", "add", "element", "inet", TABLE, "blk", "{ " + elems + " }"])
    print(f"Da nap: mode={a.mode} n={a.n}")


def cmd_cleanup(_a):
    run(["nft", "delete", "table", "inet", TABLE], check=False)
    print("Da xoa bang bench")


def _listen(port, stop):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    s.settimeout(0.5)
    while not stop.is_set():
        try:
            c, _ = s.accept()
            c.close()
        except socket.timeout:
            pass
    s.close()


def cmd_serve(a):
    """Mo cac cong TCP de client kiem tra chan/cho phep (chay tren FIREWALL VM)."""
    stop = threading.Event()
    ths = [threading.Thread(target=_listen, args=(p, stop), daemon=True) for p in a.ports]
    for t in ths:
        t.start()
    print("Dang lang nghe:", a.ports, "(Ctrl+C de dung)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop.set()


def cmd_accuracy_setup(a):
    """Rule mau: DROP cac cong 'block', ACCEPT cac cong 'allow' (de do do chinh xac)."""
    reset_table()
    for p in a.block:
        run(["nft", "add", "rule", "inet", TABLE, CHAIN, "tcp", "dport", str(p), "drop"])
    for p in a.allow:
        run(["nft", "add", "rule", "inet", TABLE, CHAIN, "tcp", "dport", str(p), "accept"])
    print("Block:", a.block, "| Allow:", a.allow)



# ---------------------------------------------------------------- DASHBOARD API (backend FastAPI)
def http(method, path, body=None):
    """Goi API backend. Loi tra ve dang {"detail": "..."}."""
    if DRY:
        print("[dry-run]", method, API + path, json.dumps(body) if body else "")
        return None
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("detail", e.code)
        except Exception:
            msg = e.code
        sys.exit(f"API loi {method} {path}: {msg}")
    except urllib.error.URLError as e:
        sys.exit(f"Khong ket noi duoc {API}: {e.reason}")


def api_rule(name, src_ip=None, port="9999", action="drop", proto="tcp"):
    return {"name": name, "src_ip": src_ip, "dst_ip": None, "port": str(port), "proto": proto,
            "direction": "in", "action": action, "enabled": True}


def ensure_live(allow_dry=False):
    """Kiem tra backend co ap dung that vao nftables khong (dry_run = false)."""
    st = http("GET", "/api/status")
    if st is None:
        return
    print("Backend:", json.dumps(st, ensure_ascii=False))
    if st.get("dry_run") and not allow_dry:
        sys.exit("Backend dang DRY-RUN (chua tac dong nftables) -> so do hieu nang vo nghia.\n"
                 "Tat dry-run trong cau hinh backend roi chay lai, hoac them --allow-dry-run de do rieng phan API.")


def cleanup_api_rules(prefix=PREFIX):
    """Xoa cac rule do script tao (ten bat dau bang 'bench-'), roi dong bo lai."""
    rules = http("GET", "/api/rules") or []
    n = 0
    for r in rules:
        if str(r.get("name") or "").startswith(prefix):
            http("DELETE", f"/api/rules/{r['id']}")
            n += 1
    http("POST", "/api/sync")
    return n


def cmd_api_status(_a):
    ensure_live(allow_dry=True)


def cmd_api_rule_time(a):
    """Do thoi gian them N rule qua Dashboard API: tao rule (SQLite) + dong bo (nftables)."""
    ensure_live(a.allow_dry_run)
    rows = []
    for n in a.ns:
        for rep in range(a.repeat):
            cleanup_api_rules()
            t0 = time.perf_counter()
            for i in range(n):
                http("POST", "/api/rules", api_rule(f"{PREFIX}{i}", fake_ip(i)))
            t_create = time.perf_counter() - t0
            t0 = time.perf_counter()
            http("POST", "/api/sync")
            t_sync = time.perf_counter() - t0
            rows.append([n, rep, round(t_create, 6), round(t_sync, 6), round(t_create + t_sync, 6)])
            print(f"N={n:5d} rep={rep}  tao_rule={t_create:.3f}s  sync={t_sync:.4f}s  tong={t_create + t_sync:.3f}s")
    cleanup_api_rules()
    save_csv("rule_time_dashboard.csv", ["n", "rep", "create_s", "sync_s", "total_s"], rows)


def cmd_load_api(a):
    """Nap N rule qua Dashboard API de do latency/throughput cua he thong that."""
    ensure_live(a.allow_dry_run)
    cleanup_api_rules()
    if a.mode == "rules":
        for i in range(a.n):
            http("POST", "/api/rules", api_rule(f"{PREFIX}{i}", fake_ip(i), a.port))
        res = http("POST", "/api/sync")
        print(f"Da nap qua API: n={a.n}", res or "")
    else:
        print("Da don rule bench (mode none)")


def cmd_accuracy_setup_api(a):
    """Tao rule chan/cho phep mau qua Dashboard API (de do do chinh xac)."""
    ensure_live(a.allow_dry_run)
    cleanup_api_rules()
    for p in a.block:
        http("POST", "/api/rules", api_rule(f"{PREFIX}acc-block-{p}", None, p, "drop"))
    for p in a.allow:
        http("POST", "/api/rules", api_rule(f"{PREFIX}acc-allow-{p}", None, p, "accept"))
    http("POST", "/api/sync")
    print("Block:", a.block, "| Allow:", a.allow)


def cmd_cleanup_api(_a):
    print("Da xoa", cleanup_api_rules(), "rule bench qua API")

# ---------------------------------------------------------------- CLIENT side
def tcp_connect_ms(host, port, timeout=1.0):
    t0 = time.perf_counter()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        dt = (time.perf_counter() - t0) * 1000
        s.close()
        return dt
    except OSError:
        return None


def cmd_latency(a):
    """Do do tre: thoi gian bat tay TCP (ms) toi mot cong dang ACCEPT, lap nhieu lan."""
    samples = []
    for _ in range(a.count):
        v = tcp_connect_ms(a.target, a.port)
        if v is not None:
            samples.append(v)
        time.sleep(0.01)
    if not samples:
        sys.exit("Khong ket noi duoc - kiem tra cong dang mo va rule ACCEPT")
    samples.sort()
    row = [a.label, len(samples), round(statistics.mean(samples), 4),
           round(statistics.median(samples), 4),
           round(samples[int(0.95 * (len(samples) - 1))], 4),
           round(statistics.pstdev(samples), 4)]
    print("label=%s n=%d mean=%.3fms median=%.3fms p95=%.3fms std=%.3f" % tuple(row))
    save_csv("latency.csv", ["label", "samples", "mean_ms", "median_ms", "p95_ms", "std_ms"], [row])


def cmd_throughput(a):
    """Do thong luong bang iperf3 (can 'iperf3 -s' tren firewall VM)."""
    if not shutil.which("iperf3") and not DRY:
        sys.exit("Chua cai iperf3: sudo apt install iperf3")
    rows = []
    for rep in range(a.repeat):
        out, _ = run(["iperf3", "-c", a.target, "-p", str(a.port), "-t", str(a.time), "-J"])
        if DRY:
            continue
        j = json.loads(out)
        mbps = j["end"]["sum_received"]["bits_per_second"] / 1e6
        rows.append([a.label, rep, round(mbps, 2)])
        print(f"{a.label} rep={rep}: {mbps:.1f} Mbit/s")
    if rows:
        save_csv("throughput.csv", ["label", "rep", "mbps"], rows)


def cmd_accuracy(a):
    """Thu ket noi toi tung cong; so sanh ket qua thuc te voi ky vong -> ma tran nham lan."""
    tp = tn = fp = fn = 0   # 'duong tinh' = bi chan
    rows = []
    for p in a.block + a.allow:
        expected_block = p in a.block
        blocked = tcp_connect_ms(a.target, p, timeout=a.timeout) is None
        tp += expected_block and blocked
        fn += expected_block and not blocked
        tn += (not expected_block) and (not blocked)
        fp += (not expected_block) and blocked
        rows.append([p, "block" if expected_block else "allow",
                     "blocked" if blocked else "open", expected_block == blocked])
    total = tp + tn + fp + fn
    acc = (tp + tn) / total if total else 0
    print(f"TP={tp} TN={tn} FP={fp} FN={fn}  accuracy={acc:.2%}")
    save_csv("accuracy.csv", ["port", "expected", "observed", "correct"], rows)


def cmd_nmap(a):
    """Quet cong bang nmap; luu ket qua dang text de dua vao bao cao."""
    if not shutil.which("nmap") and not DRY:
        sys.exit("Chua cai nmap: sudo apt install nmap")
    os.makedirs(RESULTS, exist_ok=True)
    out, dt = run(["nmap", "-sS", "-Pn", "-p", a.ports, a.target])
    path = os.path.join(RESULTS, f"nmap_{a.label}.txt")
    if not DRY:
        open(path, "w").write(out)
    print(out)
    print(f"Thoi gian quet: {dt:.1f}s -> {os.path.normpath(path)}")


# ---------------------------------------------------------------- CLI
def ints(s):
    return [int(x) for x in s.split(",") if x]


def main():
    global DRY, API
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true", help="chi in lenh, khong chay")
    ap.add_argument("--api", default="http://127.0.0.1:8000", help="dia chi backend FastAPI")
    sp = ap.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("rule-time", help="[FW] baseline thoi gian them rule bang nft")
    s.add_argument("--ns", type=ints, default=[10, 100, 1000])
    s.add_argument("--repeat", type=int, default=3)
    s.set_defaults(f=cmd_rule_time)

    s = sp.add_parser("load", help="[FW] nap N rule/set de do hieu nang")
    s.add_argument("--mode", choices=["none", "rules", "set"], required=True)
    s.add_argument("--n", type=int, default=100)
    s.add_argument("--port", type=int, default=9999)
    s.set_defaults(f=cmd_load)

    sp.add_parser("cleanup", help="[FW] xoa bang bench").set_defaults(f=cmd_cleanup)

    s = sp.add_parser("serve", help="[FW] mo cac cong TCP de thu")
    s.add_argument("--ports", type=ints, default=list(range(9001, 9011)))
    s.set_defaults(f=cmd_serve)

    s = sp.add_parser("accuracy-setup", help="[FW] nap rule mau cho phep thu do chinh xac")
    s.add_argument("--block", type=ints, default=[9001, 9002, 9003, 9004, 9005])
    s.add_argument("--allow", type=ints, default=[9006, 9007, 9008, 9009, 9010])
    s.set_defaults(f=cmd_accuracy_setup)

    s = sp.add_parser("latency", help="[CLIENT] do tre TCP connect")
    s.add_argument("--target", required=True)
    s.add_argument("--port", type=int, default=5201)
    s.add_argument("--count", type=int, default=500)
    s.add_argument("--label", required=True, help="vd: none-0, rules-100, set-1000")
    s.set_defaults(f=cmd_latency)

    s = sp.add_parser("throughput", help="[CLIENT] thong luong iperf3")
    s.add_argument("--target", required=True)
    s.add_argument("--port", type=int, default=5201)
    s.add_argument("--time", type=int, default=10)
    s.add_argument("--repeat", type=int, default=5)
    s.add_argument("--label", required=True)
    s.set_defaults(f=cmd_throughput)

    s = sp.add_parser("accuracy", help="[CLIENT] do chinh xac chan/cho phep")
    s.add_argument("--target", required=True)
    s.add_argument("--block", type=ints, default=[9001, 9002, 9003, 9004, 9005])
    s.add_argument("--allow", type=ints, default=[9006, 9007, 9008, 9009, 9010])
    s.add_argument("--timeout", type=float, default=1.0)
    s.set_defaults(f=cmd_accuracy)

    s = sp.add_parser("nmap", help="[CLIENT] quet cong bang nmap")
    s.add_argument("--target", required=True)
    s.add_argument("--ports", default="1-1024")
    s.add_argument("--label", required=True)
    s.set_defaults(f=cmd_nmap)

    def add_dry_flag(sub):
        sub.add_argument("--allow-dry-run", action="store_true", help="van chay khi backend dang dry-run")

    sp.add_parser("api-status", help="[API] xem trang thai backend (co dry-run khong)").set_defaults(f=cmd_api_status)

    s = sp.add_parser("api-rule-time", help="[API] do thoi gian them N rule qua Dashboard")
    s.add_argument("--ns", type=ints, default=[10, 100, 1000])
    s.add_argument("--repeat", type=int, default=3)
    add_dry_flag(s)
    s.set_defaults(f=cmd_api_rule_time)

    s = sp.add_parser("load-api", help="[API] nap N rule qua Dashboard de do hieu nang")
    s.add_argument("--mode", choices=["none", "rules"], required=True)
    s.add_argument("--n", type=int, default=100)
    s.add_argument("--port", type=int, default=9999)
    add_dry_flag(s)
    s.set_defaults(f=cmd_load_api)

    s = sp.add_parser("accuracy-setup-api", help="[API] rule mau do chinh xac qua Dashboard")
    s.add_argument("--block", type=ints, default=[9001, 9002, 9003, 9004, 9005])
    s.add_argument("--allow", type=ints, default=[9006, 9007, 9008, 9009, 9010])
    add_dry_flag(s)
    s.set_defaults(f=cmd_accuracy_setup_api)

    sp.add_parser("cleanup-api", help="[API] xoa rule bench da tao qua Dashboard").set_defaults(f=cmd_cleanup_api)

    a = ap.parse_args()
    DRY = a.dry_run
    API = a.api.rstrip("/")
    a.f(a)


if __name__ == "__main__":
    main()
