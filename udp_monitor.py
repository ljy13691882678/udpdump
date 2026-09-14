#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
udp_monitor.py —— 手机热点 UDP 实时监听器

场景:在开启热点的 Android 手机(Termux)上运行本程序，被动、实时地抓取
经过热点转发的 UDP 数据包 —— 也就是"目标设备 App 的服务器 -> 客户端"下发
到手机上的 UDP 协议包，并即时打印源/目的地址与负载内容(hex + ASCII)。

原理说明:
  手机开热点时，手机本身就是数据网关，所有连上热点设备的流量都要经过手机。
  因此用 tcpdump 在手机的对外网卡上抓包，就能看到下行 UDP 数据。

两种抓包后端:
  1. tcpdump 模式(默认，需 root):
     pkg install tcpdump     # Termux 内安装(需已 root，或使用已 root 环境)
     python3 udp_monitor.py
  2. socket 监听模式(纯 Python，无需 root):
     仅能收到 「发往本机/本网段广播/组播」 的 UDP 包，适合调试：
     python3 udp_monitor.py --fallback --port 9000

命令行参数:
  --source  IP      只显示源地址为该 IP(或网段 如 192.168.43.1/24)的包
  --dst     IP      只显示目的地址为该 IP/网段的包
  --port    N       只显示源或目的端口为 N 的包
  --udpfile         源或目的端口为 53(可配合输油改成 你的 App 服务端口)
  --raw             额外打印原始 hex 流(默认只打印可读字符)
  --fallback        使用 socket 监听后端(免 root)，见 --port/--bind
  --bind     IP     fallback 模式监听地址，默认 0.0.0.0
  --timeout  SEC    tcpdump 超时自动退出，0 表示不限(默认 0)
"""

import argparse
import re
import subprocess
import sys
import socket
import time

# 匹配 tcpdump 的数据包首行，"IP 源.port > 目的.port: UDP ..."
PKT_RE = re.compile(
    r"^\S+\s+IP\s+"
    r"(?P<src>\d{1,3}(?:\.\d{1,3}){3})\.(?P<sport>\d+)"
    r"\s+>\s+"
    r"(?P<dst>\d{1,3}(?:\.\d{1,3}){3})\.(?P<dport>\d+)"
    r".*?\bUDP(?P<detail>.*)$"
)
LENGTH_RE = re.compile(r"\blength (\d+)")
# 匹配 tcpdump -X 输出的十六进制负载行，如 "	0x0000:  68 65 6c 6c 6f"
HEX_LINE_RE = re.compile(r"^\s*0x[0-9a-fA-F]+:\s+(.*)$")


def to_ascii(hex_str: str) -> str:
    """把十六进制负载转成可打印 ASCII，无法打印的字节用 . 表示。"""
    hex_str = hex_str.strip()
    if not hex_str:
        return ""
    # 兼容两种格式:tcpdump 式的空格分隔，以及 data.hex() 式的连续串
    if " " in hex_str:
        tokens = hex_str.split()
    else:
        tokens = [hex_str[i:i + 2] for i in range(0, len(hex_str), 2)]
    out = []
    for h in tokens:
        try:
            b = int(h, 16)
        except ValueError:
            continue
        if 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def match_filters(flt, host, sport, dport, length):
    if flt.source and not (
        host_in(flt.source, host.s_addr)
    ):
        return False
    if flt.port and sport != flt.port and dport != flt.port:
        return False
    if flt.length and length != flt.length:
        return False
    return True


def host_in(expr: str, addr: str) -> bool:
    """判断 addr 是否属于 expr(单个 IP 或 CIDR)。"""
    try:
        ip, _, prefix = expr.partition("/")
        num = ip2int(ip)
    except ValueError:
        return False
    target = ip2int(addr)
    if prefix:
        bits = int(prefix)
        mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        return (num & mask) == (target & mask)
    return num == target


def ip2int(ip: str) -> int:
    return int.from_bytes(socket.inet_aton(ip), "big")


class Filters:
    def __init__(self, source=None, dst=None, port=None, length=None):
        self.source = source
        self.dst = dst
        self.port = port
        self.length = length


def print_packet(pkt: dict, raw: bool):
    payload_hex = pkt.get("payload_hex", "")
    ascii_str = to_ascii(payload_hex)
    hex_dump = payload_hex[:80]
    print(
        f"\n[{pkt['time']}] UDP {pkt['src']}:{pkt['sport']}"
        f" -> {pkt['dst']}:{pkt['dport']}"
        f"  len={pkt.get('length', 0)}"
    )
    if ascii_str:
        print("  ascii: " + ascii_str)
    if payload_hex:
        print("  hex  : " + hex_dump + (" ..." if len(payload_hex) > 80 else ""))


def run_tcpdump(args, filters):
    """tcpdump 文本后端：实时解析 tcpdump -X 输出。"""
    bpfs = ["udp and not src host 127.0.0.1"]
    if filters.port:
        bpfs.append(f"and port {filters.port}")
    if filters.source:
        bpfs.append(f"and src {filters.source}")
    if filters.dst:
        bpfs.append(f"and dst {filters.dst}")
    expr = " ".join(bpfs)
    cmd = ["tcpdump", "-i", "any", "-l", "-X", "-n", expr]
    print("运行 tcpdump:", " ".join(cmd), flush=True)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    cur = None  # 当前正在累积的包
    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            m = PKT_RE.match(line)
            if m:
                # 新包来了，先输出上一个累积的包
                if cur and cur.get("payload_hex"):
                    print_packet(cur, False)
                lm = LENGTH_RE.search(m.group("detail"))
                cur = {
                    "time": m.group(0).split()[0],
                    "src": m.group("src"),
                    "sport": int(m.group("sport")),
                    "dst": m.group("dst"),
                    "dport": int(m.group("dport")),
                    "length": int(lm.group(1)) if lm else 0,
                    "payload_hex": "",
                }
                continue
            hm = HEX_LINE_RE.match(line)
            if hm and cur is not None:
                # 只保留 2 个十六进制字符的字节 token，去掉行尾的 ascii 显示列
                tokens = [
                    t for t in hm.group(1).split()
                    if re.fullmatch(r"[0-9a-fA-F]{2}", t)
                ]
                cur["payload_hex"] += " ".join(tokens) + " "
                continue
            # tcpdump 的 IPv6 或其它告警行，静默忽略
        proc.wait()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        proc.terminate()
    # 收尾输出
    if cur and cur.get("payload_hex"):
        print_packet(cur, False)


def run_socket_fallback(args):
    """免 root 的 socket 监听后端：接收发往本机或本网段广播/组播的 UDP。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.bind if args.bind else "0.0.0.0", args.port))
    print(f"[fallback] 监听 {args.bind or '0.0.0.0'}:{args.port} (仅能收到发往本机的 UDP)", flush=True)
    try:
        while True:
            data, addr = s.recvfrom(65535)
            pkt = {
                "time": time.strftime("%H:%M:%S"),
                "src": addr[0],
                "sport": addr[1],
                "dst": args.bind or "0.0.0.0",
                "dport": args.port,
                "length": len(data),
                "payload_hex": data.hex(),
            }
            print_packet(pkt, args.raw)
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description="手机热点 UDP 实时监听器")
    ap.add_argument("--source", default=None, help="只显示源地址为该 IP/网段 的包")
    ap.add_argument("--dst", default=None, help="只显示目的地址为该 IP/网段 的包")
    ap.add_argument("--port", type=int, default=None, help="只显示源或目的端口为 N 的包")
    ap.add_argument("--udpfile", type=int, default=None, help="别名：与 --port 相同")
    ap.add_argument("--length", type=int, default=None, help="只显示 payload 长度为该值的包")
    ap.add_argument("--raw", action="store_true", help="额外打印原始 hex 流")
    ap.add_argument("--fallback", action="store_true", help="使用免 root 的 socket 监听后端")
    ap.add_argument("--bind", default="0.0.0.0", help="fallback 模式监听地址")
    ap.add_argument("--timeout", type=int, default=0, help="tcpdump 最大运行秒数(0 不限)")
    args = ap.parse_args()

    # 让 stdout 逐行实时刷新(即使在管道/后台运行时也能即时显示)
    sys.stdout.reconfigure(line_buffering=True)

    port = args.port or args.udpfile
    filters = Filters(source=args.source, dst=args.dst, port=port, length=args.length)

    print("=" * 60)
    print(" 手机热点 UDP 实时监听")
    print(" 提示:抓到的是 服务器->客户端 下发的 UDP 数据包")
    print("=" * 60)

    if args.fallback:
        run_socket_fallback(args)
        return

    # 检查 tcpdump 是否可用
    try:
        subprocess.run(["which", "tcpdump"], check=True,
                       capture_output=True)
    except subprocess.CalledProcessError:
        print("[错误] 未找到 tcpdump。请在 Termux 中安装: pkg install tcpdump", file=sys.stderr)
        print("       或使用免 root 的 fallback 模式: --fallback --port <端口>", file=sys.stderr)
        sys.exit(1)

    run_tcpdump(args, filters)


if __name__ == "__main__":
    main()