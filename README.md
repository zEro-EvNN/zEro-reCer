# zEro raCer

> HTTP/1.1 last-byte & HTTP/2 single-packet race condition tester.
> Made by EvNN / saMan

I got tired of writing throwaway scripts every time I needed to test a race condition. This is the cleaned-up version I actually use in CTFs and bug bounties.

## Features

- **H1 Last-Byte:** Syncs all requests with a `threading.Barrier`, sends everything but the last byte, then drops the last byte on all of them at the exact same millisecond.
- **H2 Single-Packet:** Shoves all HTTP/2 streams into a single TCP packet. The server can't even pick them apart on the wire.
- **Keep-Alive:** Reuses sockets so you don't burn through file descriptors.
- **Smart Detection:** Doesn't just check status codes. It hashes the body and compares it against the baseline to catch soft-divergences.

## Install

```bash
pip install requests h2 brotli
```

## Usage

**Basic H1 burst:**
```bash
python racer.py -u http://target/api -d '{"code":"FREE"}' -n 50
```

**H2 single packet with custom session:**
```bash
python racer.py -u https://target/api -c "sess=123" --spa -n 100
```

**Proxy through Burp:**
```bash
python racer.py -u https://target/api --proxy http://127.0.0.1:8080 --insecure
```

## Disclaimer

Only use this on systems you own or have explicit permission to test. I am not responsible if you get banned, blocked, or arrested. Don't be an idiot. `fSociety.`
