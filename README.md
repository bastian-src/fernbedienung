# fernbedienung

```
         ____             __          ___                        
        / __/__ _______  / /  ___ ___/ (_)__ ___  __ _____  ___ _
       / _// -_) __/ _ \/ _ \/ -_) _  / / -_) _ \/ // / _ \/ _ `/
      /_/  \__/_/ /_//_/_.__/\__/\_,_/_/\__/_//_/\_,_/_//_/\_, / 
                                                          /___/
```

fernbedienung allows you to transmit certain keyboard inputs from one or more
hosts to other hosts. On the receiving host, a keyboard event is generated.

The communication is TLS-secured and via central server instance.

## Run the server

Generate a server TLS certificate with:

```
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=localhost"
```

Define accepted authentication-keys in a file `./authorized_hosts`:

```
my-key-asdfs
second-key-fsdaf
thisias-another-key
```

The server expects a new client to send a valid key.

Use docker-compose:

```
docker compose up -d
```

## Run the client

Clients can run in sender and receiver mode. A client needs a valid
authentication string and the server certificate.

I'd advise you to use a venv:

```
pip install -r requirements.txt
```

Run this to get help:

```
python3 client.py --help
```

### Connect as receiver

Example receiver mode:

```
python3 client.py receiver myauthstring --server-addr localhost --server-port 9595 --server-cert-file-path ./server.crt
```

### Connect as sender

Example sender mode:

```
python3 client.py send myauthstring --server-addr localhost --server-port 9595 --server-cert-file-path ./server.crt
```


## Misc

I'm also providing a simple Windows batch script which makes it easier
to install and run fernbedienung on Windows machines. Just execute:

```
start.bat send myauthstring --server-addr localhost --server-port 9595 --server-cert-file-path ./server.crt
```
