import os
import sys
import time
import json
import socket
import logging
import argparse
import subprocess
import threading
import signal
from multiprocessing import Process, JoinableQueue, cpu_count, Manager
from scapy.all import sniff, sendp, IP, TCP, Raw, Ether

# =======================
# 1. 系統路徑與環境初始化
# =======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# 配置全局日誌系統，增加進程名稱標籤 [3]
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(processName)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

try:
    import src.settings as settings
    from src.Packet import Packet
    from src.os_recorder import templateSynthesis
    from src.os_deceiver import OsDeceiver
    from src.port_deceiver import PortDeceiver
    from src.response import get_shared_learner
    from src.fingerprint_utils import gen_key
    from src import l7_tracker
except ImportError as e:
    logging.error(f"❌ 致命初始化錯誤：缺少核心架構組件：{e}")
    sys.exit(1)

# =======================
# 2. 核心工作進程 (Packet Worker)
# =======================
def packet_worker(queue, args, host_ip, connection_states, template_dict, pair_dict, shared_fingerprint_proxy):
    """
    完全在獨立工作進程區域運行的執行邏輯，整合所有欺騙引擎 [4]。
    """
    # 將共享學習器代理連結至本地進程上下文 [4, 5]
    get_shared_learner(shared_fingerprint_proxy)
    
    # 根據掃描模式預先初始化引擎，避免在循環內重複創建 [6, 7]
    deceiver_engine = None
    if args.scan == "od":
        deceiver_engine = OsDeceiver(target_host=args.host, target_os=args.os, nic=args.nic)
    elif args.scan == "pd":
        deceiver_engine = PortDeceiver(interface_ip=host_ip, os_name=args.os or "linux", 
                                       ports_config=args.status, nic=args.nic)

    while True:
        pkt_data = queue.get()
        if pkt_data is None:  # 接收到終止信號
            queue.task_done()
            break
        
        try:
            # 模式 1: 作業系統指紋欺騙 (OS Deception)
            if args.scan == "od" and deceiver_engine:
                pkt_obj = Packet(pkt_data)
                pkt_obj.interface = args.nic
                pkt_obj.unpack()
                proto = pkt_obj.l4 if pkt_obj.l4 else pkt_obj.l3
                if proto:
                    key, _ = gen_key(proto, pkt_data)
                    # 調用 OsDeceiver 邏輯進行指紋合成回應 [8]
                    deceiver_engine.process_single_packet(pkt_obj, proto, key) 

            # 模式 2: 埠號與服務欺騙 (Port Deception)
            elif args.scan == "pd" and deceiver_engine:
                # 調用 PortDeceiver 的內部封包處理器，包含規則檢查與 JA3 分析 [9]
                deceiver_engine._handle_packet(pkt_data)

            # 模式 3: 模板合成學習 (Template Synthesis)
            elif args.scan == "ts":
                packet_obj = Packet(pkt_data)
                packet_obj.interface = args.nic
                packet_obj.unpack()
                proto = packet_obj.l4 if packet_obj.l4 else packet_obj.l3
                if proto:
                    # 建立請求/回應對並持久化為指紋模板 [10, 11]
                    templateSynthesis(packet_obj, proto.upper(), template_dict, pair_dict, 
                                      host_ip, base_path=args.dest, enable_l7=True)

        except Exception as e:
            logging.debug(f"⚠️ 工作進程處理封包時發生錯誤：{e}")
        finally:
            queue.task_done()

# =======================
# 3. 攔截引擎與並行調度
# =======================
def run_sniffing_engine(args, host_ip):
    packet_queue = JoinableQueue(maxsize=10000)
    
    # 初始化 Manager 結構以實現跨進程數據共享 [12, 13]
    manager = Manager()
    connection_states = manager.dict()
    template_dict = manager.dict()
    pair_dict = manager.dict()
    shared_fingerprint_proxy = manager.dict()
    
    # 同步視覺化儀表板數據 [13]
    l7_tracker.l7_data = manager.dict()
    l7_tracker.ja3_map = manager.dict()
    l7_tracker.ua_map = manager.dict()

    num_workers = max(1, cpu_count() - 1)
    workers = []
    
    for i in range(num_workers):
        p = Process(
            target=packet_worker,
            args=(packet_queue, args, host_ip, connection_states, template_dict, pair_dict, shared_fingerprint_proxy),
            name=f"Worker-{i}"
        )
        p.daemon = True
        p.start()
        workers.append(p)

    def producer(pkt):
        try:
            if pkt.haslayer(IP):
                packet_queue.put(bytes(pkt), block=False)
        except:
            pass # 抑制高流量時的隊列溢出錯誤 [14]

    logging.info(f"🚀 並行欺騙架構已啟動，監聽網卡：{args.nic}")
    
    sniffer_timeout = args.te * 60 if args.te else 300
    if not args.no_gui:
        # 在守護執行緒中運行監聽器，以便主進程渲染 UI [14]
        sniff_thread = threading.Thread(
            target=lambda: sniff(iface=args.nic, filter="ip", prn=producer, store=False, timeout=sniffer_timeout),
            daemon=True
        )
        sniff_thread.start()
        l7_tracker.launch_plot() # 啟動即時統計圖表 [15]
    else:
        sniff(iface=args.nic, filter="ip", prn=producer, store=False, timeout=sniffer_timeout)

    # 停止序列：清理進程池 [16]
    for _ in range(num_workers):
        packet_queue.put(None)
    packet_queue.join()
    
    if args.scan == "ts":
        save_templates(args.dest, template_dict)

def save_templates(dest_path, template_dict):
    """持久化合成的指紋模板 [17]"""
    os.makedirs(dest_path, exist_ok=True)
    try:
        native_dict = dict(template_dict)
        for proto, records in native_dict.items():
            outdata = {k.hex() if isinstance(k, bytes) else str(k): v.hex() if isinstance(v, bytes) else str(v) 
                       for k, v in records.items() if v}
            if outdata:
                out_file = os.path.join(dest_path, f"{str(proto).lower()}_record.txt")
                with open(out_file, "w") as f:
                    json.dump(outdata, f, indent=2)
        logging.info(f"📦 合成指紋數據已儲存至：{dest_path}")
    except Exception as e:
        logging.error(f"❌ 儲存指紋模板失敗：{e}")

# =======================
# 4. 系統輔助功能
# =======================
def set_nic_config(nic):
    """啟用網卡混雜模式以攔截流量 [18]"""
    try:
        subprocess.run(["ip", "link", "set", nic, "promisc", "on"], check=True)
        logging.info(f"🔁 網卡 {nic} 已進入混雜模式 (Promiscuous Mode)。")
    except Exception as e:
        logging.warning(f"⚠️ 無法自動設置混雜模式：{e}")

def get_host_ip(nic):
    """獲取網卡目前的 IP 位址 [19]"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        res = s.getsockname()
        s.close()
        return res
    except:
        return "127.0.0.1"

# =======================
# 5. 主程式入口
# =======================
def main():
    parser = argparse.ArgumentParser(description="🛡️ Camouflage Cloak: 高效能狀態欺騙引擎")
    parser.add_argument("--scan", choices=["ts", "od", "pd"], required=True, 
                        help="模式：ts (學習), od (OS 欺騙), pd (埠號欺騙)")
    parser.add_argument("--host", help="目標主機 IP (預設為本機 IP)")
    parser.add_argument("--nic", help="監聽網卡 (預設使用 settings.py 配置)")
    parser.add_argument("--dest", help="儲存/讀取指紋的路徑")
    parser.add_argument("--os", help="要模擬的作業系統 (win10, linux 等)")
    parser.add_argument("--status", help="埠號配置 (JSON 字串)")
    parser.add_argument("--te", type=int, default=5, help="運行時長 (分鐘)")
    parser.add_argument("--no-gui", action="store_true", help="關閉視覺化儀表板")
    
    args = parser.parse_args()
    
    # 套用 settings.py 的預設值 [20]
    args.nic = args.nic or settings.NIC_PROBE
    args.host = args.host or get_host_ip(args.nic)
    args.dest = args.dest or settings.OS_RECORD_PATH
    
    set_nic_config(args.nic)
    run_sniffing_engine(args, args.host)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("\n🛑 操作員終止程式。啟動安全結束序列。")
        sys.exit(0)
