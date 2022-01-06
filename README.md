# TlsChannelTest
Testing https://github.com/marianobarrios/tls-channel and related TLS stuff.
Sortof example code.
Run SimpleBlockingServer and SimpleBlockingClient.
They generate and save RSA keys, then attempt to form a connection, ask you if you want to trust the new certs, and save them to keystores so they won't ask next time.
Uses TlsChannel.  You can swap out the TCP code for ConsoleChannel (and copy paste messages from one console to the other and back), as an example of using TLS over non-TCP mechanisms.

MIT license.
