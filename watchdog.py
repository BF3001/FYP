import subprocess
import time
import redis
import sys
import psutil

class ComponentController:
    def __init__(self):
        self.redis_process = None
        self.captrue_process = None
        self.getinfo_process = None
        self.gui_process = None
        self.redis_host = "localhost"
        self.redis_port = 6379
        self.redis_container_name = "redis1"
        self.max_retry = 5
        self.check_interval = 10
        self.debug = False  # 设置为 True 开启调试信息
        self.component_status = {
            'redis': 'stopped',
            'captrue': 'stopped',
            'getinfo': 'stopped',
            'gui': 'stopped',
        }

    def log(self, msg):
        if self.debug:
            print(f"[DEBUG] {msg}")

    def start_redis(self):
        print("Starting Redis using docker-compose...")
        try:
            subprocess.run(
                ['docker-compose', '-f', '/FinalProject/tmp/redis/docker-compose.yml', 'up', '-d'],
                check=True
            )
            time.sleep(5)
            if not self.check_redis_health():
                raise Exception("Redis health check failed.")
            self.component_status['redis'] = 'running'
            print("Redis started successfully.")
        except Exception as e:
            self.component_status['redis'] = 'failed'
            print(f"Error starting Redis: {e}")
            sys.exit(1)

    def check_redis_health(self):
        for _ in range(self.max_retry):
            try:
                r = redis.Redis(host=self.redis_host, port=self.redis_port)
                r.ping()
                return True
            except redis.ConnectionError:
                print("Redis not available, retrying...")
                time.sleep(2)
        return False

    def start_captrue(self):
        try:
            self.captrue_process = subprocess.Popen(
                ['/FinalProject/tmp/captrue/captrue'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(5)
            if not self.check_process_health(self.captrue_process):
                raise Exception("Captrue health check failed.")
            self.component_status['captrue'] = 'running'
            print("Captrue started.")
        except Exception as e:
            self.component_status['captrue'] = 'failed'
            print(f"Error starting captrue: {e}")
            sys.exit(1)

    def start_getinfo(self):
        try:
            self.getinfo_process = subprocess.Popen(
                ['/FinalProject/tmp/info/getinfo'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(5)
            if not self.check_process_health(self.getinfo_process):
                raise Exception("Getinfo health check failed.")
            self.component_status['getinfo'] = 'running'
            print("Getinfo started.")
        except Exception as e:
            self.component_status['getinfo'] = 'failed'
            print(f"Error starting getinfo: {e}")
            sys.exit(1)

    def start_gui(self):
        try:
            self.gui_process = subprocess.Popen(
                ['/FinalProject/py_env/bin/python3', '/FinalProject/tmp/gui/gui.py']
            )
            time.sleep(5)
            if not self.check_process_health(self.gui_process):
                raise Exception("GUI health check failed.")
            self.component_status['gui'] = 'running'
            print("GUI started.")
        except Exception as e:
            self.component_status['gui'] = 'failed'
            print(f"Error starting GUI: {e}")
            sys.exit(1)

    def check_process_health(self, process):
        return process and process.poll() is None

    def get_memory_usage_mb(self, process):
        if process and process.poll() is None:
            try:
                proc = psutil.Process(process.pid)
                return round(proc.memory_info().rss / (1024 * 1024), 2)
            except Exception:
                return "N/A"
        return "N/A"

    def parse_docker_memory(self, mem_str):
        try:
            # e.g., "14.72MiB / 1.94GiB"
            value = mem_str.split('/')[0].strip().upper()
            self.log(f"Raw Docker MemUsage: {value}")
            if value.endswith("KIB"):
                return round(float(value.replace("KIB", "")) / 1024, 2)
            elif value.endswith("MIB"):
                return round(float(value.replace("MIB", "")), 2)
            elif value.endswith("GIB"):
                return round(float(value.replace("GIB", "")) * 1024, 2)
            elif value.endswith("B"):
                return round(float(value.replace("B", "")) / (1024 * 1024), 2)
            else:
                return "N/A"
        except Exception as e:
            self.log(f"Failed to parse memory: {e}")
            return "N/A"

    def get_redis_container_memory_mb(self):
        try:
            result = subprocess.check_output(
                ['docker', 'stats', '--no-stream', '--format', '{{.MemUsage}}', self.redis_container_name],
                text=True
            ).strip()
            return self.parse_docker_memory(result)
        except Exception as e:
            self.log(f"Docker stats failed: {e}")
            return "N/A"

    def get_redis_container_disk_usage(self):
        try:
            result = subprocess.check_output(
                ['docker', 'exec', self.redis_container_name, 'du', '-sh', '/data'],
                text=True
            ).strip()
            return result.split()[0]
        except Exception as e:
            self.log(f"Redis disk usage failed: {e}")
            return "Unknown"

    def stop_captrue(self):
        if self.captrue_process:
            self.captrue_process.terminate()
            self.captrue_process = None
            self.component_status['captrue'] = 'stopped'
            print("Captrue stopped.")

    def stop_getinfo(self):
        if self.getinfo_process:
            self.getinfo_process.terminate()
            self.getinfo_process = None
            self.component_status['getinfo'] = 'stopped'
            print("Getinfo stopped.")

    def stop_gui(self):
        if self.gui_process:
            self.gui_process.terminate()
            self.gui_process = None
            self.component_status['gui'] = 'stopped'
            print("GUI stopped.")

    def stop_redis(self):
        try:
            subprocess.run(
                ['docker-compose', '-f', '/FinalProject/tmp/redis/docker-compose.yml', 'down'],
                check=True
            )
            self.component_status['redis'] = 'stopped'
            print("Redis container stopped.")
        except subprocess.CalledProcessError:
            print("Error stopping Redis.")

    def restart_component(self, name):
        print(f"Restarting {name}...")
        getattr(self, f"stop_{name}")()
        getattr(self, f"start_{name}")()

    def display_component_status(self):
        print(f"\n===== Status @ {time.strftime('%Y-%m-%d %H:%M:%S')} =====")
        print("-" * 60)

        redis_mem = self.get_redis_container_memory_mb()
        print(f"Redis      | Status: {self.component_status['redis']:<8} | Memory: {redis_mem} MB")

        print(f"Captrue    | Status: {self.component_status['captrue']:<8} | Memory: {self.get_memory_usage_mb(self.captrue_process)} MB")
        print(f"Getinfo    | Status: {self.component_status['getinfo']:<8} | Memory: {self.get_memory_usage_mb(self.getinfo_process)} MB")
        print(f"GUI        | Status: {self.component_status['gui']:<8} | Memory: {self.get_memory_usage_mb(self.gui_process)} MB")

        print(f"Redis Disk Usage: {self.get_redis_container_disk_usage()}")
        print("-" * 60)

    def monitor_components(self):
        while True:
            time.sleep(self.check_interval)
            self.display_component_status()

            if not self.check_process_health(self.captrue_process):
                self.component_status['captrue'] = 'failed'
                self.restart_component('captrue')

            if not self.check_process_health(self.getinfo_process):
                self.component_status['getinfo'] = 'failed'
                self.restart_component('getinfo')

            if not self.check_process_health(self.gui_process):
                self.component_status['gui'] = 'failed'
                self.restart_component('gui')

    def stop_all(self):
        self.stop_captrue()
        self.stop_getinfo()
        self.stop_gui()
        self.stop_redis()

    def run(self):
        self.start_redis()
        self.start_captrue()
        self.start_getinfo()
        self.start_gui()
        self.monitor_components()

if __name__ == '__main__':
    controller = ComponentController()
    try:
        controller.run()
    except KeyboardInterrupt:
        print("Interrupted. Cleaning up...")
        controller.stop_all()

