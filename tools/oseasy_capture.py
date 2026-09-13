#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
Os-Easy 多媒体网络教室 —— 教师端/学生端「全端口」抓包与解析工具
================================================================
本脚本用于在机房环境中抓取 Os-Easy（噢易）教师端 <-> 学生端 的通信，
覆盖基于 skin/core.conf 与逆向结论整理出的**全部相关端口**，并内置解析，
可直接识别：频道广播(7777)、屏幕广播(7778)、管控报文(8040)、
通道服务器注册/匹配(8002/8003) 等关键流量。

------------------------------------------------------------------
依赖：Wireshark 自带的 tshark（Windows 安装 Wireshark 时会带 Npcap）
------------------------------------------------------------------
用法（把本脚本拷到机房电脑，管理员身份运行 CMD/PowerShell）：

  1) 列出网卡（找出正在用的网卡号）
     python oseasy_capture.py ifaces

  2) 抓包（默认 120 秒，只抓 Os-Easy 相关端口，推荐）
     python oseasy_capture.py capture -i 5 -t 120 -o oseasy.pcapng

  3) 全量抓包（不过滤，文件较大，但不会漏）
     python oseasy_capture.py capture -i 5 -t 120 -o all.pcapng --all

  4) 解析已抓到的包（关键！会打印端口分布 + 解码关键报文）
     python oseasy_capture.py parse oseasy.pcapng

  5) 只列出脚本覆盖的端口清单
     python oseasy_capture.py ports

  6) 附加抓本地回环（8045 / 9030 等本机 IPC）
     python oseasy_capture.py capture -i 5 -t 60 -o lo.pcapng --loopback

参数说明：
  -i / --iface   网卡（tshark -D 的编号或名字，如 5 或 "\Device\NPF_{...}"）
  -t / --time    抓包时长（秒），默认 120
  -o / --out     输出文件（.pcapng）
  --all          不过滤端口（全量抓）
  --loopback     额外加抓 Npcap Loopback 适配器（Windows）

提示：
  * 抓包需要【管理员权限】，否则 tshark 会报权限错误。
  * 学生机在普通交换网络下只能抓到「发给自己的单播 + 广播 + 组播」；
    想抓「教师发给别的学生机的单播（如 8040 管控）」，
    需要交换机镜像端口，或直接在目标学生机上运行本脚本。
  * 通道服务器(8002) 是 TCP 明文 HTTP，解析时会直接把服务器 IP 打印出来。
"""

from __future__ import print_function

import os
import sys
import re
import json
import time
import shutil
import struct
import argparse
import subprocess

VERSION = "1.1"

# ----------------------------------------------------------------------
# 端口表  (port, proto, 说明)
#   来源: skin/core.conf  +  逆向分析结论(10~13 号报告)
# ----------------------------------------------------------------------
PORTS = [
    # ===== 教师 <-> 学生 核心通道 =====
    (7777, "udp", "频道广播 teacherip（每3秒，收件人 255.255.255.255）"),
    (7771, "udp", "频道扫描/上线通告（组播 229.9.x.x，载荷 'teacher'）"),
    (7778, "udp", "屏幕广播（组播 229.1.x.x，自定义头 + H.264 裸流）"),
    (8040, "udp", "★ 管控主通道 UdpMessageControllerPort（16B头 + JSON）"),
    (8045, "udp", "DeviceControl 本地 IPC（127.0.0.1，回环）"),
    (9030, "udp", "npd-auto 本地 IPC（回环）"),
    # ===== 服务器通信 =====
    (8002, "tcp", "★ 通道服务器 VdiChannelServerPort（channel_register / channel_match）"),
    (8003, "tcp", "注册服务器 RegisterServerPort"),
    (9003, "tcp", "ConnectPort"),
    (443,  "tcp", "DaasServerPort / HTTPS"),
    (80,   "tcp", "HomeWorkServerPort"),
    (8555, "tcp", "FileNodeManagerPort"),
    (9979, "tcp", "FileReportPort"),
    (9100, "tcp", "FileTransferPort"),
    (9101, "tcp", "SharedDeskTopAppBindPort"),
    (9201, "tcp", "StudentDemoPort"),
    (9202, "tcp", "StudentDemoVerityPort"),
    (9001, "tcp", "TalkbackServerPort"),
    (9997, "tcp", "OuterDataPort"),
    # ===== 辅助 UDP =====
    (8888, "udp", "MacroPort"),
    (8889, "udp", "LocalAudioPort"),
    (8908, "udp", "AudioUdpVerityPort"),
    (8898, "udp", "MacUdpVerityPort"),
    (7788, "udp", "ScreenUdpVerityPort"),
]

# cmdType 速查（用于解析 8040 等 16B 头报文）
CMDTYPE_HINT = {
    500: "行为管控(网络限制/应用/USB/键盘)",
    0x13: "新学生上线补发-管控(19)",
    0x19: "补发类(25)",
    0x1c: "发送学生参数配置 StuSet(28)",
    0x42: "更新学生标识 UpdataStudentSign(66)",
    0x0b: "向新学生发呼叫 SendCallSign(11)",
    0x1d: "屏幕广播相关(29)",
}


# ----------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------
def is_windows():
    return os.name == "nt"


def is_admin():
    """检测是否管理员/root 权限（抓包所需）"""
    try:
        if is_windows():
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def find_tshark():
    """定位 tshark.exe"""
    p = shutil.which("tshark")
    if p:
        return p
    if is_windows():
        candidates = [
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"D:\Program Files\Wireshark\tshark.exe",
            r"D:\Wireshark\tshark.exe",
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c
    else:
        for c in ("/usr/bin/tshark", "/usr/local/bin/tshark", "/usr/sbin/tshark"):
            if os.path.isfile(c):
                return c
    return None


def die_tshark_missing():
    print("=" * 68)
    print("[X] 未找到 tshark（Wireshark 命令行工具）。")
    print("")
    print("请先安装 Wireshark（https://www.wireshark.org/download.html）：")
    print("  * 安装时务必勾选 'Npcap'（抓包驱动）")
    print("  * 默认会一并安装 tshark 到 C:\\Program Files\\Wireshark\\")
    print("")
    print("安装后重开 CMD，再运行本脚本。")
    print("=" * 68)
    sys.exit(1)


def build_bpf(all_mode=False):
    """构造 BPF 抓包过滤器"""
    if all_mode:
        return None
    parts = []
    for port, proto, _ in PORTS:
        parts.append("%s port %d" % (proto, port))
    return "(" + " or ".join(parts) + ")"


# ----------------------------------------------------------------------
# 子命令: ports
# ----------------------------------------------------------------------
def cmd_ports(args):
    print("=" * 72)
    print("Os-Easy 抓包覆盖端口清单（共 %d 个）" % len(PORTS))
    print("=" * 72)
    print("%-8s %-6s %s" % ("PORT", "PROTO", "说明"))
    print("-" * 72)
    for port, proto, desc in sorted(PORTS):
        print("%-8d %-6s %s" % (port, proto.upper(), desc))
    print("-" * 72)
    print("提示: 也可用 --all 抓全部端口")


# ----------------------------------------------------------------------
# 子命令: ifaces
# ----------------------------------------------------------------------
def cmd_ifaces(args):
    tshark = find_tshark()
    if not tshark:
        die_tshark_missing()
    print("=" * 68)
    print("可用网卡列表（tshark -D）")
    print("=" * 68)
    subprocess.call([tshark, "-D"])
    print("=" * 68)
    print("请把上面的【编号】或【名字】用 -i 传给 capture 子命令。")
    print("一般选择你正在上网/连着机房的物理网卡。")


# ----------------------------------------------------------------------
# 子命令: capture
# ----------------------------------------------------------------------
def cmd_capture(args):
    tshark = find_tshark()
    if not tshark:
        die_tshark_missing()

    if not is_admin():
        print("[!] 警告：当前可能不是管理员权限，抓包会失败！")
        print("    Windows 请右键『以管理员身份运行』CMD/PowerShell。")
        print("")

    out = args.out or ("oseasy_%s.pcapng" % time.strftime("%Y%m%d_%H%M%S"))
    bpf = build_bpf(args.all)

    print("=" * 68)
    print("开始抓包")
    print("  网卡      : %s" % args.iface)
    print("  时长      : %d 秒" % args.time)
    print("  输出      : %s" % out)
    if bpf:
        print("  过滤(端口): %s ... (共 %d 个端口)" % (bpf[:60], len(PORTS)))
    else:
        print("  过滤      : 无（全量抓包，文件可能较大）")
    print("=" * 68)
    print("建议操作：")
    print("  * 教师端：开机 -> 登录 -> 选择频道 -> 点一次『禁用网络/屏幕广播』")
    print("  * 学生端：开机 -> 自动上线；再手动重启一次（触发补发）")
    print("")

    common = [
        tshark,
        "-i", str(args.iface),
        "-w", out,
        "-a", "duration:%d" % args.time,
    ]
    if args.loopback:
        # Windows 回环适配器（Npcap 提供）
        common += ["-i", r"\Device\NPF_Loopback"]

    if bpf:
        common += ["-f", bpf]

    t0 = time.time()
    try:
        subprocess.call(common)
    except KeyboardInterrupt:
        print("\n[!] 用户中断抓包。")
    dt = time.time() - t0

    print("")
    print("[OK] 抓包结束，用时 %.0f 秒，文件: %s" % (dt, out))
    if os.path.isfile(out):
        size = os.path.getsize(out)
        print("     文件大小: %.2f MB" % (size / 1024.0 / 1024.0))
        if size < 2048:
            print("     [!] 文件几乎为空——可能没抓到包：")
            print("         - 确认网卡选对 / 管理员权限 / 是否有流量")
    print("")
    print(">>> 下一步：运行解析命令查看关键报文：")
    print("    python %s parse %s" % (os.path.basename(sys.argv[0]), out))


# ----------------------------------------------------------------------
# 子命令: parse
# ----------------------------------------------------------------------
TSHARK_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "udp.srcport",
    "udp.dstport",
    "tcp.srcport",
    "tcp.dstport",
    "data.data",          # UDP/未知载荷(hex)
    "http.request.uri",
    "http.host",
    "http.response.code",
    "http.request.full_uri",
    "udp.payload",        # 备用：UDP 载荷(hex)
    "tcp.payload",        # 备用：TCP 载荷(hex)
]


def _run_tshark_fields(tshark, path):
    cmd = [tshark, "-r", path, "-T", "fields", "-E", "separator=|",
           "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print("[X] tshark 解析失败：")
        sys.stdout.write(e.output.decode("utf-8", "replace"))
        return ""
    return out.decode("utf-8", "replace")


def _hex2bytes(h):
    try:
        return bytes.fromhex(h.replace(":", ""))
    except Exception:
        return b""


def cmd_parse(args):
    tshark = find_tshark()
    if not tshark:
        die_tshark_missing()
    if not os.path.isfile(args.file):
        print("[X] 文件不存在: %s" % args.file)
        sys.exit(1)

    print("=" * 72)
    print("解析抓包: %s" % args.file)
    print("=" * 72)
    raw = _run_tshark_fields(tshark, args.file)
    if not raw.strip():
        print("[!] 没有解析出任何帧（文件为空或格式不支持）。")
        return

    port_stat = {}          # (proto,sport,dport) -> count
    src_stat = {}           # src ip -> count
    dst_stat = {}
    key_pkts = []           # 关键报文
    channels = {}           # channel -> teacher_ip
    http_hits = []          # (server_ip, uri)
    total = 0

    for line in raw.splitlines():
        if not line.strip():
            continue
        cols = line.split("|")
        while len(cols) < len(TSHARK_FIELDS):
            cols.append("")
        rec = dict(zip(TSHARK_FIELDS, cols[:len(TSHARK_FIELDS)]))
        fr = rec["frame.number"]
        t = rec["frame.time_relative"]
        ipsrc = rec["ip.src"]
        ipdst = rec["ip.dst"]
        usp = rec["udp.srcport"]
        udp_dp = rec["udp.dstport"]
        tsp_ = rec["tcp.srcport"]
        tcp_dp = rec["tcp.dstport"]
        data = rec["data.data"] or rec["udp.payload"] or rec["tcp.payload"]
        hurt = rec["http.request.uri"]
        hhost = rec["http.host"]
        hcode = rec["http.response.code"]
        hfull = rec["http.request.full_uri"]
        total += 1

        # 端口统计
        try:
            if udp_dp:
                k = ("UDP", int(float(usp or 0)), int(float(udp_dp)))
                port_stat[k] = port_stat.get(k, 0) + 1
            elif tcp_dp:
                k = ("TCP", int(float(tsp_ or 0)), int(float(tcp_dp)))
                port_stat[k] = port_stat.get(k, 0) + 1
        except Exception:
            pass
        if ipsrc:
            src_stat[ipsrc] = src_stat.get(ipsrc, 0) + 1
        if ipdst:
            dst_stat[ipdst] = dst_stat.get(ipdst, 0) + 1

        # ---- HTTP（通道服务器 8002/8003）----
        uri = hurt or hfull
        if uri and ipdst and ("8002" in (tcp_dp or "") or "8003" in (tcp_dp or "")):
            http_hits.append((ipdst, uri, hcode))

        # 兜底：8002/8003 若 tshark 未识别为 HTTP，从 TCP 载荷里找 channel_ 关键字
        if not uri and data and tcp_dp in ("8002", "8003"):
            raw_txt = _hex2bytes(data).decode("latin1", "replace")
            mm = re.search(r"(/channel_[A-Za-z]+[^ \r\n]*)", raw_txt)
            if mm and ipdst:
                http_hits.append((ipdst, mm.group(1), "(raw)"))

        b = _hex2bytes(data) if data else b""

        # ---- 7777 频道广播 ----
        if udp_dp == "7777" and b[:1] == b"{":
            try:
                j = json.loads(b.decode("utf-8", "replace"))
                if j.get("msg_id") == "teacherip":
                    channels[j.get("channel")] = j.get("teacher_ip")
                    key_pkts.append(("BROADCAST", fr, t, ipsrc, ipdst, j))
            except Exception:
                pass

        # ---- 8040 管控（16B 头 + JSON）----
        if udp_dp == "8040" and len(b) >= 16:
            cmd_type, f1, f2, plen = struct.unpack("<IIII", b[:16])
            payload = b[16:16 + plen]
            try:
                pj = json.loads(payload.decode("utf-8", "replace"))
            except Exception:
                pj = None
            key_pkts.append(("CTRL", fr, t, ipsrc, ipdst,
                             {"cmdType": cmd_type, "payload": pj,
                              "raw_prefix": payload[:4].hex()}))

        # ---- 7778 屏幕广播 ----
        if udp_dp == "7778" and len(b) >= 8:
            key_pkts.append(("SCREEN", fr, t, ipsrc, ipdst,
                             {"head": b[:16].hex(), "len": len(b)}))

    # ================= 输出报告 =================
    print("\n【一】总帧数: %d" % total)

    print("\n【二】端口分布（Top 40）")
    print("-" * 60)
    for (proto, sp, dp), c in sorted(port_stat.items(), key=lambda x: -x[1])[:40]:
        note = ""
        for p, pr, d in PORTS:
            if p == dp and pr.upper() == proto:
                note = "  <- " + d
                break
        print("%-4s %6d -> %-6d  x%-6d%s" % (proto, sp, dp, c, note))

    print("\n【三】出现的 IP（Top 20）")
    print("-" * 60)
    for ip, c in sorted(src_stat.items(), key=lambda x: -x[1])[:20]:
        print("  %-16s x%d" % (ip, c))

    print("\n【四】★ 通道服务器（8002/8003 HTTP 请求）")
    print("-" * 60)
    if http_hits:
        for srv, uri, code in http_hits[:30]:
            print("  服务器IP=%s  URI=%s%s" % (srv, uri, ("  [%s]" % code) if code else ""))
    else:
        print("  （未捕获到 8002/8003 的 HTTP 请求）")
        print("  提示：通道服务器注册是周期性的，教师端/学生端开机后多等一会；")
        print("        或确认抓包时选了正确网卡（含连接机房的那块）。")

    print("\n【五】★ 7777 频道广播（channel -> teacher_ip）")
    print("-" * 60)
    if channels:
        for ch, tip in sorted(channels.items(), key=lambda x: str(x[0])):
            print("  channel=%-6s  teacher_ip=%s" % (ch, tip))
    else:
        print("  （未捕获到 7777 广播）")

    print("\n【六】★ 关键报文（8040 管控 / 7778 屏幕广播）")
    print("-" * 60)
    shown = 0
    for tag, fr, t, src, dst, info in key_pkts:
        if tag in ("CTRL", "SCREEN"):
            shown += 1
            if tag == "CTRL":
                ct = info["cmdType"]
                hint = CMDTYPE_HINT.get(ct, "")
                print("  [8040管控] #%s t=%ss %s -> %s" % (fr, t, src, dst))
                print("             cmdType=%d(%s) %s" % (ct, hex(ct), hint))
                print("             载荷前缀=%s" % info["raw_prefix"])
                if info["payload"] is not None:
                    print("             载荷JSON=%s" % json.dumps(info["payload"], ensure_ascii=False)[:300])
            else:
                print("  [7778屏幕广播] #%s t=%ss %s -> %s  len=%d" % (fr, t, src, dst, info["len"]))
                print("             头16字节=%s" % info["head"])
            if shown >= 25:
                print("  ...（更多略）")
                break

    if shown == 0:
        print("  （未捕获到 8040 / 7778 报文）")
        print("  提示：8040 是『教师单播给某个学生』，")
        print("        若在本学生机抓，只能抓到发给自己的；抓全需镜像口。")

    print("\n" + "=" * 72)
    print("解析完成。请把本输出 + pcap 文件一起保存/反馈，便于进一步分析。")
    print("=" * 72)


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Os-Easy 教师端/学生端全端口抓包与解析工具 v%s" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python oseasy_capture.py ifaces\n"
               "  python oseasy_capture.py capture -i 5 -t 120 -o oseasy.pcapng\n"
               "  python oseasy_capture.py parse oseasy.pcapng\n"
               "  python oseasy_capture.py ports\n")
    sub = ap.add_subparsers(dest="cmd")

    p1 = sub.add_parser("ports", help="列出覆盖的端口清单")
    p1.set_defaults(func=cmd_ports)

    p2 = sub.add_parser("ifaces", help="列出可用网卡")
    p2.set_defaults(func=cmd_ifaces)

    p3 = sub.add_parser("capture", help="抓包")
    p3.add_argument("-i", "--iface", required=True, help="网卡编号或名字")
    p3.add_argument("-t", "--time", type=int, default=120, help="抓包秒数(默认120)")
    p3.add_argument("-o", "--out", default=None, help="输出 pcapng 文件")
    p3.add_argument("--all", action="store_true", help="全量抓包(不过滤端口)")
    p3.add_argument("--loopback", action="store_true", help="额外抓本地回环")
    p3.set_defaults(func=cmd_capture)

    p4 = sub.add_parser("parse", help="解析抓包文件")
    p4.add_argument("file", help="pcap/pcapng 文件")
    p4.set_defaults(func=cmd_parse)

    args = ap.parse_args()
    if not getattr(args, "func", None):
        ap.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
