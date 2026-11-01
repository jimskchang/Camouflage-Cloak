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
    """統一日誌格式，方便追蹤各 worker / main process。"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [%(processName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


configure_logging()

try:
    import src.settings as settings
    from src.Packet import Packet
    from src.fingerprint_utils import gen_key
    from src.l7_tracker_refactored import L7Tracker
    from src.os_deceiver import OsDeceiver
    from src.os_recorder import templateSynthesis
    from src.port_deceiver import PortDeceiver
    from src.response import get_shared_learner
    from src.shared_state import SharedStateFactory
except ImportError as e:
    logging.error("❌ 致命初始化錯誤：缺少核心架構組件：%s", e)
    sys.exit(1)


# =======================
# 2. 核心工作進程 (Packet Worker)
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
    if os.environ.get("DISPLAY"):
        return True
    if os.name == "nt":
        return True
    return False


def validate_runtime_args(args):
    """先驗證輸入參數，避免在高負載中處理無效 NIC/host/dest。"""
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
    """統一處理 Ctrl+C / SIGTERM，讓多進程與 sniffer 能安全停止。"""

    def handle_signal(signum, _frame):
        logging.warning("⚠️ 收到中斷信號 %s，開始安全關閉...", signum)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, handle_signal)
        except (ValueError, OSError):
            pass


def build_deceiver(args, nic, host_ip, scan_mode):
    """按掃描模式建立對應的欺騙引擎。"""
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
    """在獨立工作進程中處理封包，並統一管理欺騙引擎與共享狀態。"""
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
            logging.debug("⚠️ 工作進程處理封包時發生錯誤：%s", exc)
            shared_state.increment_error_count()
        finally:
            queue.task_done()


# =======================
# 3. 攔截引擎與並行調度
# =======================
def run_sniffing_engine(args, host_ip):
    """啟動工作程序與 sniffer，並在退出前導出結果。"""
    stop_event = threading.Event()
    install_signal_handlers(stop_event)

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

    logging.info("🚀 並行欺騙架構已啟動，監聽網卡：%s", args.nic)

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
                logging.warning("⚠️ No GUI display detected; disabling dashboard and continuing in CLI mode")
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
        logging.error("❌ Sniffer runtime error: %s", exc)
        stop_event.set()
    finally:
        if not stop_event.is_set():
            stop_event.set()
        for _ in range(num_workers):
            packet_queue.put(None)
        packet_queue.join()
        for worker in workers:
            worker.join(timeout=3)

    return finalise_runtime(shared_state, args)


def finalise_runtime(shared_state, args):
    """Centralize shutdown and export logic for all runtime modes."""
    logging.info(
        "📊 Processing complete. Stats: packets=%s errors=%s",
        shared_state.packet_count.value,
        shared_state.error_count.value,
    )

    if args.scan == "ts":
        save_templates(args.dest, shared_state)

    export_ja3_log(args.dest, args.nic, shared_state)
    try:
        export_l7_data(shared_state)
    except Exception as exc:
        logging.warning("⚠️ Final export cleanup failed: %s", exc)
    return 0


def save_templates(dest_path, shared_state):
    """持久化合成的指紋模板。"""
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
        logging.info("📦 合成指紋數據已儲存至：%s", dest_path)
    except Exception as e:
        logging.error("❌ 儲存指紋模板失敗：%s", e)


def export_ja3_log(dest_path, nic, shared_state):
    """匯出多進程安全 JA3 記錄。"""
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
    """在關閉前匯出 L7 tracker 資料。"""
    try:
        tracker = L7Tracker(shared_state)
        tracker.export()
        logging.info("✅ L7 tracker data exported")
    except Exception as e:
        logging.warning("⚠️ Failed to export L7 data: %s", e)


# =======================
# 4. 系統輔助功能
# =======================
def set_nic_config(nic):
    """啟用網卡混雜模式，若未支援或權限不足則只記錄警告。"""
    if not nic:
        logging.warning("⚠️ 未指定 NIC，跳過混雜模式設定")
        return

    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True, capture_output=True, text=True)
        logging.info("🔁 網卡 %s 已進入混雜模式 (Promiscuous Mode)。", nic)
    except FileNotFoundError:
        logging.warning("⚠️ 'ip' 指令不可用，無法自動啟用混雜模式")
    except subprocess.CalledProcessError as e:
        logging.warning("⚠️ 無法自動設置混雜模式：%s", e)


def get_host_ip(nic):
    """嘗試從指定網卡獲取有效路由的本機 IP。"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# =======================
# 5. 主程式入口
# =======================
def build_parser():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak: 高效能狀態欺騙引擎")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, help="模式：ts (學習), od (OS 欺騙), pd (埠號欺騙)")
    parser.add_argument("--host", help="目標主機 IP (預設為本機 IP)")
    parser.add_argument("--nic", help="監聽網卡 (預設使用 settings.py 配置)")
    parser.add_argument("--dest", help="儲存/讀取指紋的路徑")
    parser.add_argument("--os", help="要模擬的作業系統 (win10, linux 等)")
    parser.add_argument("--status", help="埠號配置 (JSON 字串)")
    parser.add_argument("--te", type=int, default=5, help="運行時長 (分鐘)")
    parser.add_argument("--no-gui", action="store_true", help="關閉視覺化儀表板")
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

    if args.scan == "pd" and not args.status:
        logging.warning("⚠️ pd mode started without --status; using default empty port map")

    set_nic_config(args.nic)
    return run_sniffing_engine(args, args.host)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logging.info("\n🛑 操作員終止程式。啟動安全結束序列。")
        raise SystemExit(0)
    except ValueError as exc:
        logging.error("❌ 參數驗證失敗：%s", exc)
        raise SystemExit(2)
