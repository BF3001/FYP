import argparse, os, sys, time, threading, random, string, json, csv
import statistics

try:
    import redis
except ImportError:
    print("Please install: pip install redis", file=sys.stderr)
    sys.exit(1)


def make_payload(size,
                 src_ip="192.168.1.10",
                 dst_ip="93.184.216.34",
                 proto="TCP",
                 sport=12345,
                 dport=80):

    base = {
        "ts": time.time(),
        "src": src_ip,
        "dst": dst_ip,
        "proto": proto,
        "sport": sport,
        "dport": dport,
        "uuid": "".join(random.choices(string.ascii_letters + string.digits, k=16)),
    }
    s = json.dumps(base, separators=(",", ":"))
    if len(s) < size:
        pad = "".join(random.choices(string.ascii_letters + string.digits, k=size - len(s)))
        s = s[:-1] + ',"pad":"' + pad + '"}'
    return s


class Worker(threading.Thread):

    def __init__(self, idx, r, channel, rate_per_sec, size, duration, stats, lock):
        super().__init__(daemon=True)
        self.idx = idx
        self.r = r
        self.channel = channel
        self.rate = rate_per_sec
        self.size = size
        self.duration = duration
        self.stats = stats
        self.lock = lock
        self.stop = threading.Event()

    def run(self):
        start = time.monotonic()
        sent = 0
        lat_sum = 0.0
        lat_cnt = 0

        while not self.stop.is_set() and (time.monotonic() - start) < self.duration:
            t0 = time.monotonic()
            try:
                self.r.publish(self.channel, make_payload(self.size))
                ok = True
            except Exception:
                ok = False
            t1 = time.monotonic()

            if ok:
                sent += 1
                lat_sum += (t1 - t0) * 1000.0
                lat_cnt += 1

                with self.lock:
                    self.stats["sent"][self.idx] = sent
                    avg_ms = lat_sum / lat_cnt
                    self.stats["lat_ms"][self.idx] = (avg_ms, 0.0)

            if self.rate > 0:
                sleep_time = max(0.0, (1.0 / self.rate) - (time.monotonic() - t0))
                if sleep_time > 0:
                    time.sleep(sleep_time)


def build_redis(host: str, port: int) -> redis.Redis:
    return redis.Redis(host=host, port=port)


def main():
    ap = argparse.ArgumentParser(description="LLNTA Load Generator (concurrency / rate / payload size)")
    ap.add_argument("--channel", default="raw_packet_channel", help="Redis channel to publish")
    ap.add_argument("--redis-host", default=os.getenv("REDIS_HOST", "127.0.0.1"))
    ap.add_argument("--redis-port", type=int, default=int(os.getenv("REDIS_PORT", "6379")))
    ap.add_argument("--concurrency", "-c", type=int, default=4, help="Number of concurrent workers")
    ap.add_argument("--rate", "-r", type=float, default=100.0, help="Total messages per second (split across workers)")
    ap.add_argument("--bytes", "-b", type=int, default=256, help="Payload size (bytes) per message")
    ap.add_argument("--duration", "-d", type=int, default=60, help="Test duration (seconds)")
    ap.add_argument("--print-every", type=int, default=1, help="Print interval (seconds)")
    ap.add_argument("--csv", default="", help="Optional CSV path for per-second stats")
    args = ap.parse_args()

    r = build_redis(args.redis_host, args.redis_port)
    try:
        r.ping()
    except Exception as e:
        print(f"[FATAL] Cannot connect to Redis at {args.redis_host}:{args.redis_port}: {e}", file=sys.stderr)
        sys.exit(2)

    stats = {
        "sent": [0] * args.concurrency,
        "lat_ms": [(0.0, 0.0)] * args.concurrency,
    }
    lock = threading.Lock()
    per_worker_rate = args.rate / max(1, args.concurrency)

    workers = []
    for i in range(args.concurrency):
        w = Worker(i, r, args.channel, per_worker_rate, args.bytes, args.duration, stats, lock)
        w.start()
        workers.append(w)

    csv_writer = None
    csv_file = None
    if args.csv:
        csv_file = open(args.csv, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["time", "concurrency", "rate_total", "bytes", "total_sent", "sent_per_sec", "pub_latency_ms_avg"])

    t0 = time.monotonic()
    last_report = t0
    last_total = 0
    while time.monotonic() - t0 < args.duration:
        time.sleep(0.1)
        now = time.monotonic()
        if now - last_report >= args.print_every:
            with lock:
                cur_total = sum(stats["sent"])
                lat_means = [m for (m, s) in stats["lat_ms"] if m > 0]
            delta = cur_total - last_total
            lat_avg = (sum(lat_means) / len(lat_means)) if lat_means else 0.0
            per_sec = delta / (now - last_report)
            ts = time.strftime("%H:%M:%S")
            print(f"{ts} sent/s={per_sec:.1f} total={cur_total} pub_latency_ms~avg={lat_avg:.2f}")

            if csv_writer:
                csv_writer.writerow([ts, args.concurrency, args.rate, args.bytes, cur_total, f"{per_sec:.2f}", f"{lat_avg:.3f}"])

            last_total = cur_total
            last_report = now

    for w in workers:
        w.stop.set()
    for w in workers:
        w.join()

    with lock:
        grand_total = sum(stats["sent"])
        lat_means = [m for (m, s) in stats["lat_ms"] if m > 0]
    lat_avg = (sum(lat_means) / len(lat_means)) if lat_means else 0.0

    print("\n=== Summary ===")
    print(f"channel={args.channel}")
    print(f"concurrency={args.concurrency}  rate_total={args.rate}/s  bytes={args.bytes}  duration={args.duration}s")
    print(f"total_sent={grand_total}  avg_pub_latency_ms={lat_avg:.2f}")
    for i, (m, s) in enumerate(stats["lat_ms"]):
        sent_i = stats["sent"][i]
        if sent_i > 0:
            print(f"  worker#{i}: sent={sent_i}  pub_ms_avg={m:.2f}")

    if csv_file:
        csv_file.close()


if __name__ == "__main__":
    main()

