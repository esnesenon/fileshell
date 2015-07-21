# fileshell
fileshell.py -- a File-IO based remote shell, for use where there is no direct communication
				channel between the attacker and the owned target, but they can communicate
				by writing and reading files to/from a remote share/file server etc.
				
				Usage: python fileshell.py share_root {-c target | -s}
				share_root: the path to the root directory where the files for communication
				will be located.
				-c target: client mode, connect to target
				-s: server mode, listen for requests

				Tested to work on python 2.7. Does not require administrative privileges.

				Composed of a single client (runs on attacker machine) and one or more servers
				(run on compromised machines).

				Features:
				1. Client-server communication starts with a DH handshake for every new session, generating an encryption and a signing key.
				2. All communications after the handshake are AES-128 encrypted with the generated
				encryption key, and signed using HMAC-SHA256 with the signing key.
				3. Client side features shell-like behaviour, with extra commands:
					a. cc <hostname>: changes context (starts new session) to that of hostname.
					b. exit: exits current session gracefully.
					
