# Copyright (c) 2026, International Committee of the Red Cross and contributors
# For license information, please see license.txt

"""Makes http://localhost:8080 reach the Keycloak service from inside the bench's dev container.

Keycloak names its issuer after the address it is called on, and the app pins one issuer. The browser
can reach only localhost:8080 and the bench only keycloak:8080, so without this no single issuer works
for both. This forwards bytes and leaves the Host header alone, so Keycloak sees localhost:8080 from both.
"""

import argparse
import socket
import threading

BUFFER_BYTES = 65536


def _pipe(source: socket.socket, target: socket.socket) -> None:
	try:
		while data := source.recv(BUFFER_BYTES):
			target.sendall(data)
	except OSError:
		pass
	finally:
		# Both ends: the other direction's thread is blocked reading and has to wake up too.
		source.close()
		target.close()


def _forward(client: socket.socket, target_host: str, target_port: int) -> None:
	try:
		upstream = socket.create_connection((target_host, target_port))
	except OSError as e:
		print(f"Cannot reach {target_host}:{target_port}: {e}", flush=True)
		client.close()
		return
	threading.Thread(target=_pipe, args=(client, upstream), daemon=True).start()
	threading.Thread(target=_pipe, args=(upstream, client), daemon=True).start()


def main() -> None:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--listen-port", type=int, default=8080)
	parser.add_argument("--target-host", default="keycloak")
	parser.add_argument("--target-port", type=int, default=8080)
	args = parser.parse_args()

	server = socket.create_server(("127.0.0.1", args.listen_port))
	print(f"localhost:{args.listen_port} -> {args.target_host}:{args.target_port}", flush=True)
	while True:
		client, _address = server.accept()
		_forward(client, args.target_host, args.target_port)


if __name__ == "__main__":
	main()
