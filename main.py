import argparse
import ipaddress
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
from multiprocessing import JoinableQueue, Process, cpu_count
from queue import Empty, Full

from scapy.all import IP, get_if_list, sniff

# =======================
# 1. 系統路徑與環境初始化
# =======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def configure_logging():
    """统一日志格式，便于在生产环境中排查 worker、network 和 shutdown 问题。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [%(processName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )


configure_logging()

try:
    import src.settings as settings
    from src.Packet import Packet
    from src.fingerprint_utils import gen_key
    from src.l7_tracker import L7Tracker
    from src.os_deceiver import OsDeceiver
    from src.os_recorder import templateSynthesis
    from src.port_deceiver import PortDeceiver
    from src.response import get_shared_learner
    from src.shared_state import SharedStateFactory
except ImportError as e:
    logging.exception("❌ 致命初始化錯誤：缺少核心架構組件：%s", e)
    raise SystemExit(1)


# =======================
# 2. 运行时验证与安全约束
# =======================
def is_valid_ipv4(value):
    if not value:
        return False
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_nic(nic):
    if not nic:
        return False
    try:
        return nic in get_if_list()
    except Exception:
        return False


def ensure_writable_directory(path):
    if not path:
        return False
    try:
        os.makedirs(path, exist_ok=True)
        test_file = os.path.join(path, ".camouflage_cloak_write_test")
        with open(test_file, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(test_file)
        return True
    except Exception:
        return False


def supports_gui():
    return bool(os.environ.get("DISPLAY") or os.name == "nt")


def require_root_for_capture():
    if os.name == "nt":
        return True
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def validate_interface_and_routing(nic, host_ip):
    """Validate device existence and route reachability before starting sniffing."""
    if not validate_nic(nic):
        raise ValueError(f"Network interface '{nic}' is unavailable or invalid")

    if host_ip and not is_valid_ipv4(host_ip):
        raise ValueError(f"Invalid host IP: {host_ip}")

    if host_ip and host_ip != "127.0.0.1":
        route_cmd = ["ip", "route", "get", host_ip]
        try:
            proc = subprocess.run(route_cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0:
                logging.warning(
                    "⚠️ No route to host %s via interface %s; capture may still start but traffic may be unreachable",
                    host_ip,
                    nic,
                )
            else:
                route_output = proc.stdout.strip()
                logging.info("📡 Route validation for %s: %s", host_ip, route_output)
        except FileNotFoundError:
            logging.warning("⚠️ 'ip' command not available; skipping route validation")


def validate_runtime_args(args):
    """先验证输入参数，避免在高负载中处理无效 NIC/host/dest。"""
    if args.nic and not validate_nic(args.nic):
        raise ValueError(f"Invalid NIC: {args.nic}")

    if args.host and not is_valid_ipv4(args.host):
        raise ValueError(f"Invalid host IP: {args.host}")

    if args.te is not None and args.te <= 0:
        raise ValueError("--te must be greater than 0 minutes")

    if args.status:
        try:
            parsed = json.loads(args.status)
            if not isinstance(parsed, (dict, list)):
                raise ValueError("--status must decode to a JSON object or array")
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid JSON for --status: {exc}") from exc

    if args.dest:
        args.dest = os.path.abspath(args.dest)
        if not ensure_writable_directory(args.dest):
            raise ValueError(f"Destination path is not writable: {args.dest}")

    return args


def log_runtime_context(args):
    logging.info(
        "🧭 Runtime context: scan=%s nic=%s host=%s dest=%s gui=%s timeout_min=%s",
        args.scan,
        args.nic,
        args.host,
        args.dest,
        not args.no_gui,
        args.te,
    )


# =======================
# 3. Packet safety and shutdown handling
# =======================
def safe_packet_payload(pkt_data):
    """Reject malformed or suspicious packet payloads before parsing."""
    if pkt_data is None:
        return None
    if not isinstance(pkt_data, (bytes, bytearray)):
        return None

    packet = bytes(pkt_data)
    if len(packet) < 14:
        return None
    return packet


def install_signal_handlers(stop_event):
    """统一处理 Ctrl+C / SIGTERM，允许 worker 与 sniffer 安全退出。"""

    def handle_signal(signum, _frame):
        logging.warning("⚠️ 收到中断信号 %s，开始安全关机...", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handle_signal)
        except (ValueError, OSError):
            pass


def shutdown_workers(workers, packet_queue, timeout=5.0):
    """Graceful worker shutdown with bounded wait."""
    for _ in workers:
        try:
            packet_queue.put_nowait(None)
        except Exception:
            pass

    packet_queue.join()

    for worker in workers:
        if worker.is_alive():
            worker.terminate()
            worker.join(timeout=timeout)

    alive = [w for w in workers if w.is_alive()]
    if alive:
        logging.warning("⚠️ %s worker(s) did not terminate cleanly", len(alive))


# =======================
# 4. Deceiver creation and packet processing
# =======================
def build_deceiver(args, nic, host_ip, scan_mode):
    """按扫描模式创建对应的欺骗引擎。"""
    if scan_mode == "od":
        return OsDeceiver(target_host=args.host, target_os=args.os, nic=nic)
    if scan_mode == "pd":
        return PortDeceiver(
            interface_ip=host_ip,
            os_name=args.os or "linux",
            ports_config=args.status,
            nic=nic,
        )
    return None


def packet_worker(queue, args, shared_state, stop_event):
    """在独立工作进程中处理包，并统一管理共享状态与欺骗引擎。"""
    host_ip = shared_state.get_config("host")
    scan_mode = shared_state.get_config("scan_mode")
    nic = shared_state.get_config("nic")
    dest = shared_state.get_config("dest")
    enable_l7 = bool(shared_state.get_config("enable_gui"))

    try:
        get_shared_learner(shared_state)
        deceiver_engine = build_deceiver(args, nic, host_ip, scan_mode)
    except Exception as exc:
        logging.exception("❌ Worker initialization failed for mode=%s: %s", scan_mode, exc)
        stop_event.set()
        return

    while not stop_event.is_set():
        try:
            pkt_data = queue.get(timeout=0.5)
        except Empty:
            continue

        if pkt_data is None:
            queue.task_done()
            break

        packet = safe_packet_payload(pkt_data)
        if packet is None:
            queue.task_done()
            continue

        try:
            shared_state.increment_packet_count()

            if scan_mode == "od" and deceiver_engine:
                pkt_obj = Packet(packet)
                pkt_obj.interface = nic
                pkt_obj.unpack()
                proto = pkt_obj.l4 if pkt_obj.l4 else pkt_obj.l3
                if proto:
                    key, _ = gen_key(proto, packet)
                    deceiver_engine.process_single_packet(pkt_obj, proto, key)

            elif scan_mode == "pd" and deceiver_engine:
                deceiver_engine._handle_packet(packet)

            elif scan_mode == "ts":
                packet_obj = Packet(packet)
                packet_obj.interface = nic
                packet_obj.unpack()
                proto = packet_obj.l4 if packet_obj.l4 else packet_obj.l3
                if proto:
                    templateSynthesis(
                        packet_obj,
                        proto.upper(),
                        shared_state,
                        host_ip,
                        base_path=dest,
                        enable_l7=enable_l7,
                    )

        except Exception as exc:
            logging.debug("⚠️ 工作进程处理封包时发生错误：%s", exc)
            shared_state.increment_error_count()
        finally:
            queue.task_done()


# =======================
# 5. Sniffer and runtime lifecycle
# =======================
def run_sniffing_engine(args, host_ip):
    """启动 worker 与 sniffer，并在退出前导出结果。"""
    stop_event = threading.Event()
    install_signal_handlers(stop_event)

    if not require_root_for_capture():
        raise PermissionError(
            "Root privileges are required to enable promiscuous mode and capture packets on a network interface."
        )

    validate_interface_and_routing(args.nic, host_ip)
    log_runtime_context(args)

    packet_queue = JoinableQueue(maxsize=10000)
    shared_state = SharedStateFactory.create()
    shared_state.update_config(
        scan_mode=args.scan,
        nic=args.nic,
        host=host_ip,
        dest=args.dest,
        enable_gui=not args.no_gui,
        timeout=args.te * 60 if args.te else 300,
    )

    logging.info("✅ SharedState initialized with unified multiprocessing infrastructure")

    num_workers = max(1, cpu_count() - 1)
    workers = []
    for i in range(num_workers):
        process = Process(
            target=packet_worker,
            args=(packet_queue, args, shared_state, stop_event),
            name=f"Worker-{i}",
        )
        process.daemon = True
        process.start()
        workers.append(process)

    def producer(pkt):
        if stop_event.is_set() or not pkt or not pkt.haslayer(IP):
            return

        payload = bytes(pkt)
        if len(payload) < 14:
            return

        try:
            packet_queue.put_nowait(payload)
        except Full:
            try:
                packet_queue.get_nowait()
                packet_queue.put_nowait(payload)
            except Exception:
                pass
        except Exception:
            pass

    logging.info("🚀 并行欺骗架构已启动，监听网卡：%s", args.nic)

    sniffer_timeout = args.te * 60 if args.te else 300
    sniff_kwargs = {
        "iface": args.nic,
        "filter": "ip",
        "prn": producer,
        "store": False,
        "timeout": sniffer_timeout,
        "stop_filter": lambda pkt: stop_event.is_set(),
    }

    try:
        if not args.no_gui:
            if not supports_gui():
                logging.warning("⚠️ 未检测到 GUI 显示环境，自动回退到 CLI 模式")
                args.no_gui = True

            if not args.no_gui:
                sniff_thread = threading.Thread(
                    target=sniff,
                    kwargs=sniff_kwargs,
                    daemon=True,
                )
                sniff_thread.start()

                try:
                    l7_tracker_ui = L7Tracker(shared_state)
                    l7_tracker_ui.launch_plot()
                except Exception as exc:
                    logging.warning("⚠️ GUI dashboard startup failed, falling back to CLI mode: %s", exc)
                    args.no_gui = True
                    stop_event.set()
                    return finalise_runtime(shared_state, args)

                return finalise_runtime(shared_state, args)

        sniff(**sniff_kwargs)
    except Exception as exc:
        logging.exception("❌ Sniffer runtime error: %s", exc)
        stop_event.set()
    finally:
        if not stop_event.is_set():
            stop_event.set()
        shutdown_workers(workers, packet_queue)

    return finalise_runtime(shared_state, args)


def finalise_runtime(shared_state, args):
    """Centralize shutdown and export logic for all runtime modes."""
    logging.info(
        "📊 Processing complete. Stats: packets=%s errors=%s",
        shared_state.packet_count.value,
        shared_state.error_count.value,
    )

    try:
        if args.scan == "ts":
            save_templates(args.dest, shared_state)
    except Exception as exc:
        logging.exception("❌ Failed to export templates: %s", exc)

    try:
        export_ja3_log(args.dest, args.nic, shared_state)
    except Exception as exc:
        logging.exception("❌ Failed to export JA3 log: %s", exc)

    try:
        export_l7_data(shared_state)
    except Exception as exc:
        logging.exception("❌ Failed to export L7 data: %s", exc)

    return 0


# =======================
# 6. Export helpers
# =======================
def save_templates(dest_path, shared_state):
    """持久化合成的指纹模板。"""
    os.makedirs(dest_path, exist_ok=True)
    try:
        with shared_state.template_lock:
            native_dict = dict(shared_state.template_dict)

        for proto, records in native_dict.items():
            outdata = {
                (k.hex() if isinstance(k, bytes) else str(k)): (
                    v.hex() if isinstance(v, bytes) else str(v)
                )
                for k, v in records.items()
                if v
            }
            if outdata:
                out_file = os.path.join(dest_path, f"{str(proto).lower()}_record.txt")
                with open(out_file, "w", encoding="utf-8") as f:
                    json.dump(outdata, f, indent=2)
        logging.info("📦 合成指纹数据已存储至：%s", dest_path)
    except Exception as e:
        logging.error("❌ 保存指纹模板失败：%s", e)


def export_ja3_log(dest_path, nic, shared_state):
    """Export multiprocess-safe JA3 log from shared_state."""
    try:
        with shared_state.ja3_lock:
            if not shared_state.ja3_log:
                return
            native_dict = dict(shared_state.ja3_log)

        json_ready = {
            k: sorted(list(v)) if isinstance(v, list) else [v]
            for k, v in native_dict.items()
        }

        os.makedirs(dest_path, exist_ok=True)
        outfile = os.path.join(dest_path, f"ja3_observed_{nic}.json")
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(json_ready, f, indent=2)
        logging.info("🔐 JA3 log exported → %s", outfile)
    except Exception as e:
        logging.warning("⚠️ Failed to export JA3 log: %s", e)


def export_l7_data(shared_state):
    """在关闭前导出 L7 tracker 数据。"""
    try:
        tracker = L7Tracker(shared_state)
        tracker.export()
        logging.info("✅ L7 tracker data exported")
    except Exception as e:
        logging.warning("⚠️ Failed to export L7 data: %s", e)


# =======================
# 7. System helpers
# =======================
def set_nic_config(nic):
    """启用网卡混杂模式；若权限不足则仅记录警告。"""
    if not nic:
        logging.warning("⚠️ 未指定 NIC，跳过混杂模式设置")
        return

    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True, capture_output=True, text=True)
        logging.info("🔁 网卡 %s 已进入混杂模式 (Promiscuous Mode)。", nic)
    except FileNotFoundError:
        logging.warning("⚠️ 'ip' 命令不可用，无法自动启用混杂模式")
    except subprocess.CalledProcessError as e:
        logging.warning("⚠️ 无法自动设置混杂模式：%s", e)


def get_host_ip(nic):
    """尝试从指定网卡获取一个可用的本机 IP。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# =======================
# 8. CLI entrypoint
# =======================
def build_parser():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak: 高性能状态欺骗引擎")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, help="模式：ts (学习), od (OS 欺骗), pd (端口欺骗)")
    parser.add_argument("--host", help="目标主机 IP (默认使用本机 IP)")
    parser.add_argument("--nic", help="监听网卡 (默认使用 settings.py 配置)")
    parser.add_argument("--dest", help="存储/读取指纹的路径")
    parser.add_argument("--os", help="要模拟的操作系统 (win10, linux 等)")
    parser.add_argument("--status", help="端口配置 (JSON 字符串)")
    parser.add_argument("--te", type=int, default=5, help="运行时长 (分钟)")
    parser.add_argument("--no-gui", action="store_true", help="关闭可视化仪表板")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        args = validate_runtime_args(args)
    except ValueError as exc:
        parser.error(str(exc))

    args.nic = args.nic or settings.NIC_PROBE
    args.host = args.host or get_host_ip(args.nic)
    args.dest = args.dest or settings.OS_RECORD_PATH

    if not ensure_writable_directory(args.dest):
        raise ValueError(f"Destination path is not writable: {args.dest}")

    if not validate_nic(args.nic):
        raise ValueError(f"Network interface '{args.nic}' is unavailable or invalid")

    if not require_root_for_capture():
        raise PermissionError(
            "Root privileges are required to enable promiscuous mode and capture packets on a network interface."
        )

    validate_interface_and_routing(args.nic, args.host)

    if args.scan == "pd" and not args.status:
        logging.warning("⚠️ pd mode started without --status; using default empty port map")

    set_nic_config(args.nic)
    return run_sniffing_engine(args, args.host)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logging.info("\n🛑 操作员终止程序。启动安全结束序列。")
        raise SystemExit(0)
    except PermissionError as exc:
        logging.error("❌ 权限不足：%s", exc)
        raise SystemExit(2)
    except ValueError as exc:
        logging.error("❌ 参数验证失败：%s", exc)
        raise SystemExit(2)
    except Exception as exc:
        logging.exception("❌ 未捕获的运行时错误：%s", exc)
        raise SystemExit(1)

