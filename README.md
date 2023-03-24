# ushuttle: UDP in TCP implementation with SOCKS5/HTTP proxy support

## About
I was looking for a way to tunnel WireGuard connection through proxy servers but didn't find a good solution (extremely slow, too complex, low MTU, etc). So here is `ushuttle`.

The program is in C-S architecture: a client program runs on the local machine, listens on a UDP socket, and forwards everything it receives to the server (via either direct TCP connection or proxy server). The server then relays packets to their original destination.

This program is currently a hobby project and only serves my own needs, however, any issue report or recommendation is welcomed.

## Build
Prebuilt binaries are available in the release page. In the meantime, you can build your own copy in the standard Rusty way:

```
git clone https://github.com/dynos01/ushuttle
cd ushuttle
cargo build --release
```

## Usage
```
#On the server
ushuttle -m server -l [::]:51821 -r 127.0.0.1:51820 -k "mySuperKey"

#On the client
ushuttle -m client -l 127.0.0.1:51820 -r example.com:51821 -k "mySuperKey"
```
Then `ushuttle` will happily forward everything between udp://127.0.0.1:51820 of the local machine and udp://127.0.0.1:51820 of the remote machine via TCP.

If a proxy is needed, simply add a proxy argument to the client: `-p socks5://127.0.0.1:1080`. Proxy authentication is supported: `-p socks5://user:pass@127.0.0.1:1080`.

Warning: `ushuttle` currently does not provide any encryption. The shared key is only used for authentication, not encryption. Only use this in a trusted proxy tunnel, or your UDP traffic is already encrypted.

Since `ushuttle` is currently a hobby project, the protocol might change in the future. It's recommended to use the same version on the server and client for compatibility.

## Performance
No extensive performance tests are done, but here is a simple result by `iperf` on my local machine (i5-1240P):

- Direct connection: 7.0 Gbps (< 1% packet loss)
- Through `ushuttle`, direct TCP connection: 2.1 Gbps (< 1% packet loss)
