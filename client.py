#!/usr/bin/env python3

import socket
import argparse
from pynput import keyboard
from pynput.keyboard import Controller
import signal
import sys
import ssl
import time


ASCII_ART = r"""
         ____             __          ___
        / __/__ _______  / /  ___ ___/ (_)__ ___  __ _____  ___ _
       / _// -_) __/ _ \/ _ \/ -_) _  / / -_) _ \/ // / _ \/ _ `/
      /_/  \__/_/ /_//_/_.__/\__/\_,_/_/\__/_//_/\_,_/_//_/\_, /
                                                          /___/
:-------------------------------------::--::::+=-----------------------:
::-::--------------------------------::::------=+:---------------------::
::::::-------------------------------:::==*****=*:---------------------::
::::::-------------------------:::::-::+#%###*=+*-:--------------------::
:::::::----------------:----=*%##+-:::+%#*     =++=--------------------::
::::::::---------=++++==-:-*%@@%%%#+-:#%#+     ==+--:------------------::
:::::-::------:-===++++++=*%%%#***#%+:-=+*    +=++=++=-----------------::
::::::-::----::-*#+=+**##*#%**    **+-:::-+++++*#+++%#+-:-------------:::
::::::-:::--::-+*=    **#**%#+    ++=--:::-+#*###*+++***+=-----====---:::
:::::::-:::::-:-+=     #*=-**+*  *#+=--:::=*%%%*++=+++*#********+=-=--::+
:::::::::::-=*##+=     **----=++=++**+-::-###%%*++++=+********##***+-:-=:
:::::::::::+####*++  *#*--=*+***++**%@%*+*##%#*+=====+#%%##*#######+==--:
:::::::::::=#%%@@@%***##-+**#%%+++++==*%%#*#%*+===+==*%#%#*########*++#%%
::-===-=++*#%%%@@@%%@@%*+%#**@%=-----==%@%*##*==-=+===*#%###%######**+===
:-=+#%%%%#%%%%%@#***#@*++**%@@#=---=---#@@%##%==--==-=+*%###%%%######**==
:-=#%%@@%###%%%@*----==+=**%@@#=-------*%@@###=-====--=##%#*#%%%######*+=
-=#%%@@@%##%%%@@#----==+++*%%@#=-----:-+%@@%##*=--=+-==##%#*##%%%#####*++
-*%%%%@@%##@@@@@%----=+++*+=%%%==---::-=%@%%#%%=---+-==*#%######%%######*
-%%%%@@%%#%@@@@#++++++++=====#@=--==---=#@%%%%%+---==--+#%#####%%%+#%####
*%%%%@@@%%@@@@*=+++*#++=+++==+#%+-==---=#@@%%%%#=---=-==*%##*#%%%%%*###**
%%%%%@@@@@%@%@==+**#@@@@%#+=++%@@*------=%@@%##%*=--+---*#####%###%%###**
%%%%%%%%%%@@@@#=+%@@@@@@@@@@@%@@@#=-----=*%@%##%%=--==--=####%%###%@##***
%%%%%%@%@@@@@@@%@@@@@@@@@@@%@@@@@*==-----+#@%%#%%=--==--=*#########%%###*
%%%%%%%%@@%@@@@@@@@@@@@@@@@@%@@@%+==------+%%%%%#==--+-==+%%#######%%####
##%%%%%%@%%%@@@@@@@@@@@@@@@@@@%#*+=-----===*%%#*=+=--=--===*#######*#####
=*####%%%%@@@@@@@@@@@@@@@@@@@@%+++=-------=+#@@*%@%#*+===+*########*#%#*+
-+::-::*%@@@@%@@@@@@@@@@@@@@@@%+===--------=+%%+=%%%@##@%%%@@@%#####***==
:==:-::%%%%%@@@@@@@@@@@@@@@@@%*+==---------==*%*=%%%%#*@%%%%%%@@@%##***==
:-+:--:#%%%%%%@@@@@%@@@@@@@@%+=#**+====+=====+#*%%%%%%*%%%%%%%%@@@@@#++==
::+-:-:=#%%@%%%@@@@@@@@@@@%+===**++====++====+++%%%%%%*%%%%%%%%%%%%%%#+++
::=+:--:=#%%%%%%@@@@@@@%*+=-=#+**++===+++====++#%%%%%@#*@@@%%%%%%%%%%*==+
:::*---::*%%%@@@@@@@%+====#@@@#+**++==+**=====+#%%%%%%#*@@%*%%%%%%%%%*+==
:::=+:--::----==------=#@@@@%@@++*+==++++=====+#%%%%%%%+%%**%%%%%%%##++++
::::+---::-----=+*#%%%%@@@@@%@@%=++==+**+=====+%%%%%%%%##*++**###%%#%+===
::::==:--:=#%%%%%@@@@%@@@@@@@@@@#====++*+=====+%%%%#**#@@#***#%@@@%#*=+++
::::-+:--::*#%%%%@@@@@@@@%@@@@@@*=-==++*+====++**##%@@@******+%@@%%#+++++
:::::+-:-::+#%%%%%@@@@%%@@@@%*+=====+++++++===#%%@@@@@%++****++@@%**+====
:::::=+:--:=#%%%%@@@@%==+****=+++++=+**#*=====*%@@@@@%*++*****+@@%***=++=
::::::+---:-#%%%@@@@%#++++***=--====++++*+==+=+%@@@@@@##**#****@@@@%#+===
::::::=+:-:-*%##***##+---*++*+====+==++++*+===++#@@@@@%****#***@@@@@%++++
=:::::-+==++==*####*-:---****+===========*+++=++=%@@@@@#*******@@@@%#++++
"""


# ---------- CONFIG ----------
DEFAULT_SERVER_IP = "localhost"
DEFAULT_PORT = 9595
DEFAULT_SERVER_CERT_FILE_PATH = "./server.crt"
CLIENT_MODE_SENDER = "send"
CLIENT_MODE_RECEIVER = "receive"
# ----------------------------

# --------- PROTOCOL ---------
PROTOCOL_RESPONSE_OK = "OK"
PROTOCOL_RESPONSE_NOT_OK = "NO NO!"
PROTOCOL_RESPONSE_SENDER = "I'm a sender"
PROTOCOL_RESPONSE_RECEIVER = "I'm a receiver"
PROTOCOL_VALID_KEYS = [
    "Key.left",
    "Key.right",
    "Key.up",
    "Key.down",
    "w",
    "a",
    "s",
    "d",
    "q",
    "e",
    "r",
    "f",
]
# ----------------------------

CLIENT_MODE_TO_PROTOCOL_MAP = {
    CLIENT_MODE_SENDER: PROTOCOL_RESPONSE_SENDER,
    CLIENT_MODE_RECEIVER: PROTOCOL_RESPONSE_RECEIVER,
}


def client_mode_to_protocol(client_mode: str) -> str:
    if client_mode in CLIENT_MODE_TO_PROTOCOL_MAP.keys():
        return CLIENT_MODE_TO_PROTOCOL_MAP[client_mode]
    raise Exception("Client mode not valid")


def handle_sigint(signum, frame):
    print("\nCaught Ctrl+C! Cleaning up...")
    sys.exit(0)


def send_keys_to_server(args):
    """Reads keys from user input and sends them to the remote server via TCP."""

    def on_press(key):
        try:
            k = key.char  # single-char keys
        except AttributeError:
            k = str(key)  # special keys like Key.space
        if k in PROTOCOL_VALID_KEYS:
            try:
                tls_socket.sendall(k.encode("utf-8"))
            except Exception:
                print("Failed to send key. Server might be disconnected.")
                return False

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        tls_socket = connect_and_authenticate(args, client_socket)
        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()  # Keep listening


def receive_keys_from_server(args):
    """Receives keys over TCP and simulates them using the keyboard controller."""

    keyboard_controller = Controller()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        tls_socket = connect_and_authenticate(args, client_socket)
        print(f"Listening for incoming key commands on port {DEFAULT_PORT}...")
        while True:
            data = tls_socket.recv(1024)
            if not data:
                break
            key_str = data.decode("utf-8")
            if key_str in PROTOCOL_VALID_KEYS:
                simulate_keypress(keyboard_controller, key_str)


def simulate_keypress(keyboard_controller, key_str):
    """Simulates a keypress based on the received string."""
    try:
        if key_str.startswith("Key."):
            # Handle special keys like 'Key.space'
            key_obj = getattr(keyboard.Key, key_str.split(".")[1])
        else:
            key_obj = key_str  # regular characters
        keyboard_controller.press(key_obj)
        time.sleep(0.05)
        keyboard_controller.release(key_obj)
    except Exception as e:
        print(f"Error simulating keypress for '{key_str}': {e}")


def connect_and_authenticate(args, socket):
    print(
        f"[ ] Attempt TLS connection to {args.server_addr}:{args.server_port}.",
        end="\r",
    )
    context = ssl.create_default_context()
    context.load_verify_locations(args.server_cert_file_path)
    wrapped_socket = context.wrap_socket(socket, server_hostname=args.server_addr)
    wrapped_socket.connect((args.server_addr, args.server_port))
    print("[✓]")

    print("[ ] Attempt authentication.", end="\r")
    wrapped_socket.send(args.auth.encode())
    auth_response = wrapped_socket.recv(1024).decode()
    if auth_response != PROTOCOL_RESPONSE_OK:
        raise Exception("Sever Authentication failed!")
    print("[✓]")
    print("[ ] Attempt sending mode.", end="\r")
    wrapped_socket.send(client_mode_to_protocol(args.mode).encode())
    mode_response = wrapped_socket.recv(1024).decode()
    if mode_response != PROTOCOL_RESPONSE_OK:
        raise Exception("Sending mode failed!")
    print("[✓]")
    return wrapped_socket


def main():
    parser = argparse.ArgumentParser(
        description="fernbedienung: TCP Key Event Sender/Receiver"
    )
    parser.add_argument(
        "mode",
        choices=[CLIENT_MODE_SENDER, CLIENT_MODE_RECEIVER],
        help=f"Mode: '{CLIENT_MODE_SENDER}' to send keypresses, \
        '{CLIENT_MODE_RECEIVER}' to simulate received keypresses.",
    )
    parser.add_argument(
        "auth", type=str, help="Auth: authenticate yourself against the server."
    )
    parser.add_argument(
        "--server-addr",
        type=str,
        default=DEFAULT_SERVER_IP,
        help=f"Server IP address. Default is {DEFAULT_SERVER_IP}.",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Server port. Default is {DEFAULT_PORT}.",
    )
    parser.add_argument(
        "--server-cert-file-path",
        type=str,
        default=DEFAULT_SERVER_CERT_FILE_PATH,
        help=f"File path to the server TLS certificate. Default is {DEFAULT_SERVER_CERT_FILE_PATH}.",
    )
    args = parser.parse_args()

    print(ASCII_ART)

    print("I'll transmit any key-press event of the following valid keys:")
    print(f"  {PROTOCOL_VALID_KEYS}")
    print("Have Fun!")

    # Register the signal handler
    signal.signal(signal.SIGINT, handle_sigint)

    if args.mode == "send":
        send_keys_to_server(args)
    elif args.mode == "receive":
        receive_keys_from_server(args)


if __name__ == "__main__":
    main()
    exit(0)
