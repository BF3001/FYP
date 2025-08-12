import redis
import time
import json
import socket
import subprocess
import requests
import os
from flask import Flask, render_template, jsonify, request, send_from_directory
from threading import Thread
from scapy.all import IP, TCP, sr1
import folium
from folium import PolyLine
from datetime import datetime

app = Flask(__name__)
cached_ip_data = {}  # 長期緩存所有IP數據
live_ip_data = {}    # 活躍IP（有過期機制）
port_scan_results = {}  # 緩存端口掃描結果

WATCHDOG_STATIC_PATH = "/FinalProject/tmp/watchdog/static"


def is_private_ip(ip):
    try:
        parts = list(map(int, ip.split('.')))
    except:
        return True
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    return False


def update_ip_data():
    r = redis.StrictRedis(host='127.0.0.1', port=6379, db=0)
    pubsub = r.pubsub()
    pubsub.subscribe('five_tuple_channel')

    expire_time = 60

    for message in pubsub.listen():
        if message['type'] != 'message':
            continue
        try:
            msg_data = json.loads(message['data'].decode('utf-8'))
        except json.JSONDecodeError:
            continue

        current_time = time.time()
        src_ip = msg_data.get("src_ip")
        dst_ip = msg_data.get("dst_ip")
        app_name = msg_data.get("app", "UNKNOWN")

        for ip_key in [("src", src_ip), ("dst", dst_ip)]:
            ip_type, ip = ip_key
            if not ip or is_private_ip(ip):
                continue
            lat = msg_data.get(f"{ip_type}_lat", 0.0)
            lon = msg_data.get(f"{ip_type}_lon", 0.0)
            location = msg_data.get(f"{ip_type}_location", "Unknown")

            ip_info = {
                "location": location,
                "lat": lat,
                "lon": lon,
                "app": app_name,
                "expire_time": current_time + expire_time,
                "last_seen": current_time
            }
            live_ip_data[ip] = ip_info
            cached_ip_data[ip] = ip_info


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/get_ip_data')
def get_ip_data():
    current_time = time.time()
    expired_ips = [ip for ip, data in live_ip_data.items() if current_time > data['expire_time']]
    for ip in expired_ips:
        del live_ip_data[ip]
    return jsonify(sorted_ip_data=list(live_ip_data.items()), current_time=current_time)


@app.route('/all_cache')
def all_cache():
    return jsonify(all_data=list(cached_ip_data.items()))


@app.route('/scan')
def scan_ports():
    target_ip = request.args.get('ip')
    if not target_ip:
        return jsonify(error="Missing IP"), 400

    common_ports = [22, 23, 25, 53, 80, 443, 8080, 3389]
    open_ports = []

    for port in common_ports:
        try:
            with socket.create_connection((target_ip, port), timeout=0.5):
                open_ports.append(port)
        except:
            continue

    port_scan_results[target_ip] = open_ports
    return jsonify(ip=target_ip, open_ports=open_ports)


@app.route('/banner')
def banner_grab():
    ip = request.args.get('ip')
    ports = port_scan_results.get(ip, [80])
    result = {}

    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=2) as s:
                s.settimeout(2)
                if port == 80:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                elif port == 21:
                    s.sendall(b"\r\n")
                elif port == 25:
                    s.sendall(b"EHLO banner.local\r\n")
                banner = s.recv(1024).decode(errors='ignore')
                result[port] = banner.strip()
        except Exception as e:
            result[port] = f"Error: {str(e)}"

    return jsonify(ip=ip, banners=result)


@app.route('/webinfo')
def web_info():
    ip = request.args.get('ip')
    if not ip:
        return jsonify(error="Missing IP"), 400
    url = f"http://{ip}"
    try:
        r = requests.get(url, timeout=2)
        title = ''
        if "<title>" in r.text.lower():
            start = r.text.lower().index("<title>") + 7
            end = r.text.lower().index("</title>", start)
            title = r.text[start:end]
        return jsonify(
            ip=ip,
            status_code=r.status_code,
            server=r.headers.get("Server", "Unknown"),
            title=title.strip()
        )
    except Exception as e:
        return jsonify(ip=ip, error=str(e))


@app.route('/os_detect')
def os_detect():
    ip = request.args.get('ip')
    if not ip:
        return jsonify(error="Missing IP"), 400
    try:
        result = subprocess.run(['ping', '-c', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if 'ttl=' in result.stdout.lower():
            ttl = int(result.stdout.lower().split('ttl=')[1].split()[0])
            if ttl >= 128:
                os_type = "Windows"
            elif ttl >= 64:
                os_type = "Linux/Unix"
            else:
                os_type = "Unknown"
            return jsonify(ip=ip, ttl=ttl, guessed_os=os_type)
        else:
            return jsonify(ip=ip, error="No TTL found, host may be unreachable")
    except Exception as e:
        return jsonify(ip=ip, error=str(e))


@app.route('/tcp_fingerprint')
def tcp_fingerprint():
    ip = request.args.get('ip')
    if not ip:
        return jsonify(error="Missing IP"), 400
    try:
        pkt = IP(dst=ip)/TCP(dport=80, flags='S')
        resp = sr1(pkt, timeout=2, verbose=0)
        if resp is None or not resp.haslayer(TCP):
            return jsonify(ip=ip, error="No response")

        ttl = resp.ttl
        window = resp[TCP].window
        options = resp[TCP].options
        os_guess = "Unknown"

        if ttl >= 128 and window in [8192, 65535]:
            os_guess = "Windows"
        elif ttl >= 64 and window in [5840, 14600]:
            os_guess = "Linux"

        return jsonify(ip=ip, ttl=ttl, window=window, options=options, os_guess=os_guess)
    except Exception as e:
        return jsonify(ip=ip, error=str(e))


@app.route('/dns_lookup')
def dns_lookup():
    ip = request.args.get('ip')
    if not ip:
        return jsonify(error="Missing IP"), 400
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return jsonify(ip=ip, hostname=hostname)
    except Exception:
        return jsonify(ip=ip, error="No reverse DNS found")


@app.route('/traceroute')
def traceroute():
    ip = request.args.get('ip')
    if not ip:
        return jsonify(error="Missing IP"), 400

    try:
        os.makedirs(WATCHDOG_STATIC_PATH, exist_ok=True)
        command = ['traceroute', '-n', ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)

        hops = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] != '*':
                hops.append(parts[1])

        points = []
        for hop_ip in hops:
            try:
                resp = requests.get(f'http://ip-api.com/json/{hop_ip}', timeout=3)
                data = resp.json()
                if data['status'] == 'success':
                    lat = data.get('lat')
                    lon = data.get('lon')
                    if lat is not None and lon is not None:
                        points.append({
                            'ip': hop_ip,
                            'lat': lat,
                            'lon': lon,
                            'city': data.get('city', ''),
                            'region': data.get('regionName', ''),
                            'country': data.get('country', ''),
                            'isp': data.get('isp', '')
                        })
            except:
                continue

        m = folium.Map(location=[20, 0], zoom_start=2)
        latlons = [(p['lat'], p['lon']) for p in points]
        if latlons:
            PolyLine(latlons, color='red', weight=2, opacity=0.8).add_to(m)
            for p in points:
                popup_html = (
                    f"<b>IP:</b> {p['ip']}<br>"
                    f"<b>Location:</b> {p['city']}, {p['region']}, {p['country']}<br>"
                    f"<b>ISP:</b> {p['isp']}"
                )
                folium.Marker(
                    location=(p['lat'], p['lon']),
                    popup=folium.Popup(popup_html, max_width=300)
                ).add_to(m)

        filename = f"traceroute_map_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = os.path.join(WATCHDOG_STATIC_PATH, filename)
        m.save(output_path)

        return jsonify({"hops": points, "url": f"/traceroute_static/{filename}"})
    except Exception as e:
        return jsonify(ip=ip, error=str(e))



@app.route('/traceroute_static/<path:filename>')
def traceroute_static(filename):
    return send_from_directory(WATCHDOG_STATIC_PATH, filename)


def start_ip_data_update():
    update_ip_data()


if __name__ == '__main__':
    thread = Thread(target=start_ip_data_update)
    thread.daemon = True
    thread.start()
    app.run(debug=True, host='0.0.0.0', port=5000)

