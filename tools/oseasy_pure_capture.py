#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Os-Easy 纯 Python 抓包/自动上传/解析工具 v3（不依赖 Npcap / Wireshark）
================================================================
机房没有 Npcap 也能用！只用 Python 标准库。融合了 netctrl_capture.py 的
「抓到包就实时 POST 上传到服务器」能力。

原理（两种抓包模式）：
  [raw]    Windows 原生 raw socket (SIO_RCVALL)
           —— 抓「本机进出」的所有 IP 包(UDP+TCP)；只需【管理员权限】；不需 Npcap。
  [listen] 普通 UDP socket 绑定端口
           —— 只收「广播 / 发给本机的」UDP；不需管理员；信息较少。

上传：每收到一个关注端口的有效包，异步 POST 到服务器（可关）。

------------------------------------------------------------------
用法（管理员 CMD / PowerShell）：

  python oseasy_pure_capture.py ip
  python oseasy_pure_capture.py raw -t 120 -o oseasy.pcap
  python oseasy_pure_capture.py raw -t 120 -o oseasy.pcap --no-upload
  python oseasy_pure_capture.py raw -t 120 --upload-url http://1.2.3.4:8091/upload
  python oseasy_pure_capture.py parse oseasy.pcap
  python oseasy_pure_capture.py listen -t 120 -o listen.log
  python oseasy_pure_capture.py ports

参数：
  -t / --time   抓包秒数（默认 120）
  -o / --out    输出 pcap 文件
  --all         不过滤端口（全抓）
  --ports       自定义端口，如 7777,8040,8002
  --no-upload   关闭实时上传
  --upload-url  上传地址（默认 http://45.207.220.121:8091/upload）

注意：
  * raw 模式必须【管理员】身份运行，否则 socket 报 WinError 10013。
  * raw 模式抓不到「教师发给别的学生机」的单播（那需要交换机镜像口）；
    在被控机/教师机上运行，本机自身流量都能抓到。
"""

from __future__ import print_function

import os
import sys
import re
import json
import time
import random
import struct
import socket
import argparse
import threading
import urllib.parse
import urllib.request

VERSION = "3.0"

# ----------------------------------------------------------------------
# 端口表  (port, proto, 说明)
# ----------------------------------------------------------------------
PORTS = [
    (7777, "udp", "频道广播 teacherip（每3秒，255.255.255.255）"),
    (7771, "udp", "频道扫描/上线通告（组播 229.9.x.x，'teacher'）"),
    (7778, "udp", "屏幕广播（组播 229.1.x.x，自定义头+H.264）"),
    (8040, "udp", "★ 管控主通道 UdpMessageControllerPort（16B头+JSON）"),
    (8045, "udp", "DeviceControl 本地 IPC（127.0.0.1）"),
    (9030, "udp", "npd-auto 本地 IPC"),
    (8002, "tcp", "★ 通道服务器 VdiChannelServerPort（channel_register/match）"),
    (8003, "tcp", "注册服务器 RegisterServerPort"),
    (9003, "tcp", "ConnectPort"),
    (443,  "tcp", "DaasServerPort/HTTPS"),
    (80,   "tcp", "HomeWorkServerPort"),
    (8555, "tcp", "FileNodeManagerPort"),
    (9979, "tcp", "FileReportPort"),
    (9100, "tcp", "FileTransferPort"),
    (9101, "tcp", "SharedDeskTopAppBindPort"),
    (9201, "tcp", "StudentDemoPort"),
    (9202, "tcp", "StudentDemoVerityPort"),
    (9001, "tcp", "TalkbackServerPort"),
    (9997, "tcp", "OuterDataPort"),
    (8888, "udp", "MacroPort"),
    (8889, "udp", "LocalAudioPort"),
    (8908, "udp", "AudioUdpVerityPort"),
    (8898, "udp", "MacUdpVerityPort"),
    (7788, "udp", "ScreenUdpVerityPort"),
]

PORT_SET = set(p for p, _, _ in PORTS)

CMDTYPE_HINT = {
    500: "行为管控(网络限制/应用/USB/键盘)",
    0x13: "新学生上线补发-管控(19)",
    0x19: "补发类(25)",
    0x1c: "发送学生参数配置 StuSet(28)",
    0x42: "更新学生标识(66)",
    0x0b: "向新学生发呼叫(11)",
    0x1d: "屏幕广播相关(29)",
}

# pcap 全局头（linktype=101 = RAW IP）
PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)


# ======================================================================
# 实时上传模块（融合自 netctrl_capture.py）
# ======================================================================
UPLOAD_ENABLE = True
UPLOAD_URL = "http://45.207.220.121:8091/upload"
UPLOAD_NAME = None

# ★ 待上传数据【本地落盘目录】: 管控断网/服务器不可达时也不丢, 解除后自动补传
SPOOL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oseasy_spool")
SPOOL_MAX_FILES = 5000
_spool_seq = [0]


def _make_upload_name():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "host"
    ts = time.strftime("%Y%m%d-%H%M%S")
    rnd = random.randint(1000, 9999)
    return "%s_%s_%s" % (ip, ts, rnd)


def _ensure_spool():
    try:
        if not os.path.isdir(SPOOL_DIR):
            os.makedirs(SPOOL_DIR)
    except Exception:
        pass


def _spool_files():
    try:
        return sorted(os.listdir(SPOOL_DIR))
    except Exception:
        return []


def init_upload():
    global UPLOAD_NAME
    UPLOAD_NAME = _make_upload_name()
    _ensure_spool()


def enqueue_upload(text):
    """★ 把待上传数据【落盘】(不是只放内存): 断网期间也不丢, 恢复后自动补传"""
    if not UPLOAD_ENABLE or not text:
        return
    _ensure_spool()
    _spool_seq[0] += 1
    fn = os.path.join(SPOOL_DIR, "%013d_%05d.txt" % (int(time.time() * 1000), _spool_seq[0]))
    try:
        with open(fn, "w", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass
    files = _spool_files()
    if len(files) > SPOOL_MAX_FILES:
        for old in files[:len(files) - SPOOL_MAX_FILES]:
            try:
                os.remove(os.path.join(SPOOL_DIR, old))
            except Exception:
                pass


def _upload_one():
    files = _spool_files()
    if not files:
        return False
    path = os.path.join(SPOOL_DIR, files[0])
    try:
        with open(path, "r", encoding="utf-8") as f:
            item = f.read()
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        return True
    ok = False
    try:
        payload = item.encode("utf-8", "replace")
        q = urllib.parse.urlencode({"name": UPLOAD_NAME})
        url = UPLOAD_URL + ("&" if "?" in UPLOAD_URL else "?") + q
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "text/plain; charset=utf-8"})
        with urllib.request.urlopen(req, timeout=5) as r:
            code = r.getcode()
            r.read(64)
        ok = (code == 200)
    except Exception:
        ok = False
    if ok:
        try:
            os.remove(path)
        except Exception:
            pass
    else:
        time.sleep(1.5)
    return ok


def _uploader_loop():
    while True:
        if not UPLOAD_ENABLE:
            time.sleep(2)
            continue
        try:
            _upload_one()
        except Exception:
            pass
        time.sleep(0.05)


def start_uploader():
    try:
        t = threading.Thread(target=_uploader_loop, daemon=True)
        t.start()
    except Exception:
        pass


# ======================================================================
# 基础工具
# ======================================================================
def is_windows():
    return os.name == "nt"


def is_admin():
    try:
        if is_windows():
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def is_private(ip):
    if not ip:
        return False
    if ip.startswith("224.") or ip.startswith("239.") or ip == "0.0.0.0":
        return True
    if ip.startswith("127."):
        return False
    try:
        a = int(ip.split(".")[0]); b = int(ip.split(".")[1])
    except Exception:
        return False
    if a == 10 or (a == 192 and b == 168) or (a == 169 and b == 254):
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    return False


def parse_ports(extra):
    if not extra:
        return set(PORT_SET)
    out = set()
    for x in re.split(r"[,\s]+", extra.strip()):
        if x.isdigit():
            out.add(int(x))
    return out or set(PORT_SET)


# ======================================================================
# IP 包解析
# ======================================================================
def _parse_ip_packet(buf):
    if len(buf) < 20:
        return None
    try:
        ver_ihl = buf[0]
        if (ver_ihl >> 4) != 4:
            return None
        ihl = (ver_ihl & 0x0F) * 4
        proto = buf[9]
        src = socket.inet_ntoa(buf[12:16])
        dst = socket.inet_ntoa(buf[16:20])
        info = {"src": src, "dst": dst, "proto": proto, "sport": None,
                "dport": None, "payload": b""}
        if proto == 17 and len(buf) >= ihl + 8:
            sport, dport, ulen, _ = struct.unpack("!HHHH", buf[ihl:ihl + 8])
            payload = buf[ihl + 8:ihl + ulen] if ulen >= 8 else b""
            info.update(sport=sport, dport=dport, payload=payload)
        elif proto == 6 and len(buf) >= ihl + 20:
            sport, dport = struct.unpack("!HH", buf[ihl:ihl + 4])
            doff = (buf[ihl + 12] >> 4) * 4
            info.update(sport=sport, dport=dport, payload=buf[ihl + doff:])
        else:
            return None
        return info
    except Exception:
        return None


def analyze_payload(dport, pay):
    """识别 Os-Easy 关键报文，返回描述字符串"""
    try:
        if dport == 7777 and pay[:1] == b"{":
            j = json.loads(pay.decode("utf-8", "replace"))
            if j.get("msg_id") == "teacherip":
                return "7777频道广播 channel=%s teacher_ip=%s" % (
                    j.get("channel"), j.get("teacher_ip"))
            return "7777 JSON=" + json.dumps(j, ensure_ascii=False)
        if dport == 8040 and len(pay) >= 16:
            ct, f1, f2, plen = struct.unpack("<IIII", pay[:16])
            body = pay[16:16 + plen]
            s = "8040 cmdType=%d(%s) " % (ct, CMDTYPE_HINT.get(ct, "?"))
            try:
                s += "JSON=" + json.dumps(json.loads(body.decode("utf-8", "replace")),
                                          ensure_ascii=False)
            except Exception:
                s += "payload_prefix=" + body[:4].hex()
            return s
        if dport in (8002, 8003):
            txt = pay.decode("latin1", "replace")
            m = re.search(r"(GET|POST)\s+(\S+)", txt)
            if m:
                return "HTTP %s %s" % (m.group(1), m.group(2))
        if dport == 7778 and len(pay) >= 8:
            return "7778屏幕广播 head=" + pay[:16].hex()
    except Exception:
        pass
    return ""


def _fmt_upload(ts, info, note):
    proto = {6: "TCP", 17: "UDP"}.get(info["proto"], "?")
    pay = info["payload"]
    lines = [
        "-" * 60,
        "[%.3f] %s %s:%s -> %s:%s len=%d" % (
            ts, proto, info["src"], info["sport"], info["dst"], info["dport"], len(pay)),
        "HEX: " + pay.hex(),
    ]
    if note:
        lines.append("解析: " + note)
    return "\n".join(lines) + "\n"


# ======================================================================
# 抓包：raw 模式
# ======================================================================
def capture_raw(duration, out_path, ports, all_mode):
    if not is_windows():
        print("[!] raw 模式主要面向 Windows（SIO_RCVALL）。")
    if not is_admin():
        print("[X] raw 模式需要【管理员权限】！请右键『以管理员身份运行』后重试。")
        print("    （没有管理员权限时可用: listen 模式）")
        return False

    local_ip = get_local_ip()
    print("本机 IP: %s" % local_ip)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((local_ip, 0))
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(0.5)
    except Exception as e:
        print("[X] 创建 raw socket 失败: %s" % e)
        print("    常见原因：非管理员 / 本机IP选错 / 安全软件拦截。")
        return False

    f = open(out_path, "wb")
    f.write(PCAP_GLOBAL_HEADER)

    port_stat = {}
    total = 0
    t0 = time.time()
    print("=" * 66)
    print("raw 抓包开始，时长 %d 秒 -> %s" % (duration, out_path))
    print("过滤端口: %s" % ("全部" if all_mode else "%d 个" % len(ports)))
    if UPLOAD_ENABLE:
        print("实时上传: 开 -> %s (name=%s)" % (UPLOAD_URL, UPLOAD_NAME))
    else:
        print("实时上传: 关")
    print("（Ctrl+C 可提前结束）")
    print("=" * 66)

    try:
        while time.time() - t0 < duration:
            try:
                buf, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break
            ts = time.time()
            info = _parse_ip_packet(buf)
            if not info:
                continue
            sp, dp = info["sport"], info["dport"]
            if not all_mode and sp not in ports and dp not in ports:
                continue
            total += 1
            sec = int(ts)
            usec = int((ts - sec) * 1000000)
            f.write(struct.pack("<IIII", sec, usec, len(buf), len(buf)))
            f.write(buf)
            k = (info["proto"], sp, dp)
            port_stat[k] = port_stat.get(k, 0) + 1
            # ★ 实时上传
            note = analyze_payload(dp, info["payload"]) or analyze_payload(sp, info["payload"])
            enqueue_upload(_fmt_upload(ts - t0, info, note))
            if total % 500 == 0:
                sys.stdout.write("\r已抓 %d 包，用时 %.0fs ..." % (total, ts - t0))
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[!] 用户中断。")
    finally:
        f.close()
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        s.close()

    print("\n[OK] 抓包结束，共 %d 包 -> %s" % (total, out_path))
    print("     文件大小: %.2f MB" % (os.path.getsize(out_path) / 1024.0 / 1024.0))
    _print_quick_stat(port_stat)
    print("\n>>> 下一步： python %s parse %s" % (os.path.basename(sys.argv[0]), out_path))
    return True


# ======================================================================
# 抓包：listen 模式
# ======================================================================
def capture_listen(duration, out_path, ports):
    udp_ports = sorted(p for p, pr, _ in PORTS if pr == "udp")
    socks = []
    for p in udp_ports:
        try:
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sk.bind(("0.0.0.0", p))
            sk.settimeout(0.5)
            socks.append((p, sk))
        except Exception as e:
            print("[!] 端口 %d 无法监听: %s" % (p, e))
    if not socks:
        print("[X] 没有端口可监听。")
        return

    print("=" * 66)
    print("listen 抓包开始，时长 %d 秒 -> %s" % (duration, out_path))
    print("监听 UDP 端口: %s" % ", ".join(str(p) for p, _ in socks))
    if UPLOAD_ENABLE:
        print("实时上传: 开 -> %s (name=%s)" % (UPLOAD_URL, UPLOAD_NAME))
    print("=" * 66)

    import select
    logf = open(out_path, "w", encoding="utf-8")
    t0 = time.time()
    cnt = 0
    try:
        while time.time() - t0 < duration:
            r, _, _ = select.select([sk for _, sk in socks], [], [], 0.5)
            for sk in r:
                try:
                    data, addr = sk.recvfrom(65535)
                except Exception:
                    continue
                port = sk.getsockname()[1]
                ts = time.time() - t0
                cnt += 1
                note = analyze_payload(port, data)
                txt = data.decode("utf-8", "replace")
                line = "[%8.3f] src=%s:%d bind=%d len=%d pay=%s\n" % (
                    ts, addr[0], addr[1], port, len(data), txt.strip()[:300])
                logf.write(line); logf.flush()
                sys.stdout.write(line)
                # 上传
                enqueue_upload("[%.3f] listen bind=%d from %s:%d len=%d\nHEX: %s\n%s\n" % (
                    ts, port, addr[0], addr[1], len(data), data.hex(),
                    ("解析: " + note) if note else ""))
    except KeyboardInterrupt:
        print("\n[!] 用户中断。")
    finally:
        logf.close()
        for _, sk in socks:
            sk.close()
    print("[OK] listen 结束，共 %d 包 -> %s" % (cnt, out_path))


# ======================================================================
# 解析 pcap（纯 Python）
# ======================================================================
def read_pcap(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[:4])[0]
        if magic == 0xA1B2C3D4:
            endian, nano = "<", False
        elif magic == 0xD4C3B2A1:
            endian, nano = ">", False
        elif magic == 0xA1B23C4D:
            endian, nano = "<", True
        else:
            endian, nano = "<", False
        while True:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            sec, usec, cap, orig = struct.unpack(endian + "IIII", hdr)
            data = f.read(cap)
            if len(data) < cap:
                break
            yield sec + (usec / 1e9 if nano else usec / 1e6), data


def cmd_parse(args):
    if not os.path.isfile(args.file):
        print("[X] 文件不存在: %s" % args.file)
        sys.exit(1)
    print("=" * 70)
    print("解析: %s (纯 Python)" % args.file)
    print("=" * 70)
    port_stat = {}
    channels = {}
    http_hits = []
    ctrl_pkts = []
    total = 0
    first_t = None
    for t, pkt in read_pcap(args.file):
        total += 1
        if first_t is None:
            first_t = t
        info = _parse_ip_packet(pkt)
        if not info:
            continue
        sp, dp, pay = info["sport"], info["dport"], info["payload"]
        proto = "UDP" if info["proto"] == 17 else ("TCP" if info["proto"] == 6 else "?")
        port_stat[(proto, sp, dp)] = port_stat.get((proto, sp, dp), 0) + 1
        if dp == 7777 and pay[:1] == b"{":
            try:
                j = json.loads(pay.decode("utf-8", "replace"))
                if j.get("msg_id") == "teacherip":
                    channels[j.get("channel")] = j.get("teacher_ip")
            except Exception:
                pass
        if dp == 8040 and len(pay) >= 16:
            ct, f1, f2, plen = struct.unpack("<IIII", pay[:16])
            body = pay[16:16 + plen]
            try:
                pj = json.loads(body.decode("utf-8", "replace"))
            except Exception:
                pj = None
            ctrl_pkts.append((round(t - first_t, 3), info["src"], info["dst"], ct,
                              body[:4].hex(), pj))
        if dp in (8002, 8003) and pay:
            txt = pay.decode("latin1", "replace")
            m = re.search(r"(GET|POST)\s+(\S+)", txt)
            if m:
                http_hits.append((info["dst"], m.group(2)))
            elif "channel_" in txt:
                m2 = re.search(r"(/channel_[A-Za-z]+[^\s\r\n]*)", txt)
                if m2:
                    http_hits.append((info["dst"], m2.group(1) + " (raw)"))

    print("\n【一】总帧数: %d" % total)
    print("\n【二】端口分布")
    print("-" * 60)
    for (proto, sp, dp), c in sorted(port_stat.items(), key=lambda x: -x[1])[:40]:
        note = ""
        for p, pr, d in PORTS:
            if p == dp and pr.upper() == proto:
                note = "  <- " + d
                break
        print("%-4s %6d -> %-6d x%-6d%s" % (proto, sp, dp, c, note))
    print("\n【三】★ 通道服务器（8002/8003）")
    print("-" * 60)
    if http_hits:
        seen = set()
        for srv, uri in http_hits[:40]:
            if (srv, uri) in seen:
                continue
            seen.add((srv, uri))
            print("  服务器IP=%s  URI=%s" % (srv, uri))
    else:
        print("  （未捕获 8002/8003；注册是周期性的，多抓一会儿）")
    print("\n【四】★ 7777 频道广播")
    print("-" * 60)
    if channels:
        for ch, tip in sorted(channels.items(), key=lambda x: str(x[0])):
            print("  channel=%-6s teacher_ip=%s" % (ch, tip))
    else:
        print("  （未捕获）")
    print("\n【五】★ 8040 管控报文")
    print("-" * 60)
    if ctrl_pkts:
        for ts, src, dst, ct, pfx, pj in ctrl_pkts[:30]:
            print("  t=%ss %s -> %s  cmdType=%d(%s) %s" % (
                ts, src, dst, ct, hex(ct), CMDTYPE_HINT.get(ct, "")))
            print("     载荷前缀=%s" % pfx)
            if pj is not None:
                print("     JSON=%s" % json.dumps(pj, ensure_ascii=False)[:300])
    else:
        print("  （未捕获 8040；本机没收到管控时正常，需被控机/镜像口）")
    print("\n" + "=" * 70)


def _print_quick_stat(port_stat):
    if port_stat:
        print("\n端口分布(Top15):")
        for (proto, sp, dp), c in sorted(port_stat.items(), key=lambda x: -x[1])[:15]:
            pc = {6: "TCP", 17: "UDP"}.get(proto, str(proto))
            print("  %-4s %6d -> %-6d x%d" % (pc, sp, dp, c))


# ======================================================================
def cmd_ip(args):
    print("本机 IP: %s" % get_local_ip())
    print("主机名 : %s" % socket.gethostname())


def cmd_ports(args):
    print("=" * 66)
    print("覆盖端口（共 %d）" % len(PORTS))
    print("=" * 66)
    for p, pr, d in sorted(PORTS):
        print("%-6d %-4s %s" % (p, pr.upper(), d))


def main():
    global UPLOAD_ENABLE, UPLOAD_URL
    ap = argparse.ArgumentParser(
        description="Os-Easy 纯 Python 抓包/上传/解析工具 v%s（不依赖 Npcap）" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python oseasy_pure_capture.py ip\n"
               "  python oseasy_pure_capture.py raw -t 120 -o oseasy.pcap\n"
               "  python oseasy_pure_capture.py parse oseasy.pcap\n"
               "  python oseasy_pure_capture.py listen -t 120 -o listen.log\n")
    sub = ap.add_subparsers(dest="cmd")

    s1 = sub.add_parser("ip", help="显示本机 IP")
    s1.set_defaults(func=cmd_ip)

    s2 = sub.add_parser("ports", help="列出端口")
    s2.set_defaults(func=cmd_ports)

    s3 = sub.add_parser("raw", help="raw socket 抓包（需管理员，无需 Npcap）")
    s3.add_argument("-t", "--time", type=int, default=120, help="秒数(默认120)")
    s3.add_argument("-o", "--out", default=None, help="输出 pcap")
    s3.add_argument("--all", action="store_true", help="不过滤端口(全抓)")
    s3.add_argument("--ports", default=None, help="自定义端口,如 7777,8040,8002")
    s3.add_argument("--no-upload", action="store_true", help="关闭实时上传")
    s3.add_argument("--upload-url", default=None, help="上传地址")
    s3.set_defaults(func=None)

    s4 = sub.add_parser("listen", help="UDP 监听抓包（无需管理员，受限）")
    s4.add_argument("-t", "--time", type=int, default=120, help="秒数(默认120)")
    s4.add_argument("-o", "--out", default=None, help="输出日志")
    s4.add_argument("--no-upload", action="store_true", help="关闭实时上传")
    s4.add_argument("--upload-url", default=None, help="上传地址")
    s4.set_defaults(func=None)

    s5 = sub.add_parser("parse", help="解析 pcap（纯 Python）")
    s5.add_argument("file", help="pcap 文件")
    s5.set_defaults(func=cmd_parse)

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return

    # 上传配置
    if getattr(args, "no_upload", False):
        UPLOAD_ENABLE = False
    if getattr(args, "upload_url", None):
        UPLOAD_URL = args.upload_url
    if UPLOAD_ENABLE:
        init_upload()
        start_uploader()

    if args.cmd == "raw":
        out = args.out or ("oseasy_%s.pcap" % time.strftime("%Y%m%d_%H%M%S"))
        capture_raw(args.time, out, parse_ports(args.ports), args.all)
    elif args.cmd == "listen":
        out = args.out or ("oseasy_listen_%s.log" % time.strftime("%Y%m%d_%H%M%S"))
        capture_listen(args.time, out, None)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
