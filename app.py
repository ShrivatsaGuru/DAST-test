# app.py
import subprocess
import yaml

# Bandit will flag this as a security risk (B602)
def run_command(data):
    subprocess.run(data, shell=True)

# Semgrep will flag this as unsafe YAML loading
def load_config(config_file):
    with open(config_file, 'r') as f:
        return yaml.load(f, Loader=yaml.Loader)

run_command("ls")