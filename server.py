#!/usr/bin/env python3

import socket
import signal
import sys
import ssl
import threading
import argparse
from datetime import datetime


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

# --------- DEFAULTS ---------
DEFAULT_SERVER_CERT_FILE = "./server.crt"
DEFAULT_SERVER_KEY_FILE = "./server.key"
DEFAULT_AUTH_FILE = "./authorized_hosts"
DEFAULT_PORT = 9595
DEFAULT_MAX_CLIENTS = 5
# ----------------------------

# --------- PROTOCOL ---------
PROTOCOL_RESPONSE_OK = "OK"
PROTOCOL_RESPONSE_NOT_OK = "NO NO!"
PROTOCOL_RESPONSE_SENDER = "I'm a sender"
PROTOCOL_RESPONSE_RECEIVER = "I'm a receiver"
# ----------------------------

# --------- GLOBALS ---------
clients_lock = threading.Lock()
receiver_clients = []
# ----------------------------


def print_timed(msg: str, end="\n\r"):
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"[{time_str}]{msg}", end=end)


def handle_sigint(signum, frame):
    print_timed("\nCaught Ctrl+C! Cleaning up...")
    sys.exit(0)


def read_auths(file_name: str) -> list[str]:
    auths = []
    with open(file_name, "r") as file:
        for line in file.readlines():
            auths.append(line.strip())
    return auths


def accept_and_authenticate(server_socket, ssl_context, auths):
    newsocket, addr = server_socket.accept()
    print_timed(f"[ ] <{addr}> Attempt TLS handshake with new client", end="\r")
    wrapped_client = ssl_context.wrap_socket(newsocket, server_side=True)
    print_timed("[✓]")
    print_timed(f"[ ] <{addr}> Attempt client authorization", end="\r")
    auth_message = wrapped_client.recv(1024).decode().strip()
    if auth_message not in auths:
        wrapped_client.send(PROTOCOL_RESPONSE_NOT_OK.encode())
        print_timed("[✘]")
        raise Exception(f"Error: <{addr}> No valid client authentication")
    print_timed("[✓]")
    wrapped_client.send(PROTOCOL_RESPONSE_OK.encode())

    print_timed(f"[ ] <{addr}> Attempt determining client type", end="\r")
    type_message = wrapped_client.recv(1024).decode().strip()
    if type_message not in [PROTOCOL_RESPONSE_SENDER, PROTOCOL_RESPONSE_RECEIVER]:
        print_timed("[✘]")
        raise Exception(f"Error: <{addr}> No valid client type transmitted")
    wrapped_client.send(PROTOCOL_RESPONSE_OK.encode())

    return wrapped_client, addr, type_message


def client_thread(client_socket, addr, client_type):
    print_timed(f"[✓] <{addr}> Connected as {client_type}")

    if client_type == PROTOCOL_RESPONSE_RECEIVER:
        with clients_lock:
            receiver_clients.append(client_socket)

    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            if client_type == PROTOCOL_RESPONSE_SENDER:
                key_str = data.decode().strip()
                print_timed(f"[>] <{addr}: {key_str}")
                with clients_lock:
                    disconnected = []
                    for r in receiver_clients:
                        try:
                            r.sendall(data)
                        except Exception:
                            disconnected.append(r)

                    for r in disconnected:
                        receiver_clients.remove(r)

    except Exception as e:
        print_timed(f"[!] <{addr}> Exception in client thread: {e}")
    finally:
        print_timed(f"[x] <{addr}> Disconnected")
        with clients_lock:
            if (
                client_type == PROTOCOL_RESPONSE_RECEIVER
                and client_socket in receiver_clients
            ):
                receiver_clients.remove(client_socket)
        client_socket.close()


def run(args):
    auths = read_auths(args.auth_file_path)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        certfile=args.server_cert_file, keyfile=args.server_key_file
    )

    server_socket = socket.socket()
    server_socket.bind(("0.0.0.0", args.server_port))
    server_socket.listen(args.max_clients)

    while True:
        try:
            client_socket, addr, client_type = accept_and_authenticate(
                server_socket, context, auths
            )

            thread = threading.Thread(
                target=client_thread,
                args=(client_socket, addr, client_type),
                daemon=True,
            )
            thread.start()
        except Exception as e:
            print_timed(f"Error while accepting new client: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="fernbedienung: TCP Key Event Sender/Receiver SERVER"
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Server port. Default is {DEFAULT_PORT}.",
    )
    parser.add_argument(
        "--auth-file-path",
        type=str,
        default=DEFAULT_AUTH_FILE,
        help="List of valid client authentications.",
    )
    parser.add_argument(
        "--server-cert-file",
        type=str,
        default=DEFAULT_SERVER_CERT_FILE,
        help=f"File path to the server TLS certificate. Default is {DEFAULT_SERVER_CERT_FILE}.",
    )
    parser.add_argument(
        "--server-key-file",
        type=str,
        default=DEFAULT_SERVER_KEY_FILE,
        help=f"File path to the server TLS certificate. Default is {DEFAULT_SERVER_KEY_FILE}.",
    )
    parser.add_argument(
        "--max-clients",
        type=int,
        default=DEFAULT_MAX_CLIENTS,
        help=f"Number of simultaneous client connections. Default is {DEFAULT_MAX_CLIENTS}.",
    )
    args = parser.parse_args()
    signal.signal(signal.SIGINT, handle_sigint)

    print(ASCII_ART)

    run(args)


if __name__ == "__main__":
    main()
    exit(0)
