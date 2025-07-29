# app.py
import subprocess
import os

# --- High Severity Vulnerability ---
# Bandit ID: B602 - Using subprocess with shell=True.
# Risk: This can allow a user to execute arbitrary shell commands if the input
# is not properly sanitized. It's a classic command injection risk.
def run_shell_command(user_command):
    print(f"Executing user command: {user_command}")
    subprocess.run(user_command, shell=True)


# --- Medium Severity Vulnerability ---
# Bandit ID: B105 - Hardcoding a password in source code.
# Risk: Secrets stored in code can be easily exposed if the source code is
# ever leaked or accessed by unauthorized individuals.
def get_database_connection():
    password = "MySuperSecretPassword123"  # Hardcoded password
    print("Connecting to database...")
    # Real connection logic would use the password here
    return f"Connected with password: {password}"


# --- Low Severity Vulnerability ---
# Bandit ID: B101 - Use of the 'assert' keyword.
# Risk: Assert statements are removed when Python is run in optimized mode
# (with the -O flag), so any security checks using 'assert' can be bypassed.
def verify_admin_status(is_admin):
    assert is_admin, "User must have admin privileges!"
    print("Admin status verified.")


print("--- Running High Severity Example ---")
run_shell_command('echo "This command ran successfully."')

print("\n--- Running Medium Severity Example ---")
get_database_connection()

print("\n--- Running Low Severity Example ---")
try:
    verify_admin_status(is_admin=False)
except AssertionError as e:
    print(f"Caught expected assertion error: {e}")
