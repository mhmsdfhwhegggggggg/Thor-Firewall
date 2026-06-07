#!/usr/bin/env python3
"""
Thor Firewall Benchmark Tool
يقيس إنتاجية النظام وزمن الوصول
"""

import subprocess
import time
import threading
import statistics
import argparse

def generate_traffic(duration_sec: int, pps: int):
    """توليد حركة مرور صناعية باستخدام hping3 أو tcpreplay"""
    # هنا محاكاة بسيطة باستخدام hping3 (يجب تثبيته)
    cmd = f"sudo hping3 --fast --rand-source -S 127.0.0.1 -c {duration_sec * pps}"
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def measure_latency():
    """قياس زمن انتقال الحزمة عبر Thor (محاكاة بسيطة)"""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        start = time.perf_counter_ns()
        # إرسال حزمة وهمية للقياس
        sock.sendto(b"test", ("127.0.0.1", 80))
        end = time.perf_counter_ns()
        return (end - start) / 1000  # ميكروثانية
    except PermissionError:
        return 0.0

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pps", type=int, default=1000, help="Packets per second to generate")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    args = parser.parse_args()

    print(f"🚀 Starting benchmark: {args.pps} PPS for {args.duration}s")
    
    traffic_thread = threading.Thread(target=generate_traffic, args=(args.duration, args.pps))
    traffic_thread.start()

    latencies = []
    end_time = time.time() + args.duration
    while time.time() < end_time:
        lat = measure_latency()
        if lat > 0:
            latencies.append(lat)
        time.sleep(0.1)

    traffic_thread.join()

    if latencies:
        print("\n--- Results ---")
        print(f"Average Latency: {statistics.mean(latencies):.2f} us")
        print(f"Max Latency: {max(latencies):.2f} us")
        print(f"Min Latency: {min(latencies):.2f} us")
    else:
        print("No latency data collected. (Try running with sudo)")

if __name__ == "__main__":
    main()
