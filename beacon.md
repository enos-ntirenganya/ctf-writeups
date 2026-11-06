# Beacon: Network Forensics Writeup

- **Writeup author:** Enos Ntirenganya
- **Challenge author:** LordSudo
- **Event:** _add the event name here_
- **Category:** Network forensics
- **Difficulty / Points:** Easy / 100
- **Tools used:** `unzip`, `file`, `tshark`, `xxd`, `strings`, `python3`

## Challenge

A suspected botnet infection. `beacon.pcap` holds a captured traffic segment from the affected host. Something in there is checking in with someone it shouldn't be.

**Goal:** find the host that is beaconing to a command-and-control (C2) server, decode the traffic, and recover the flag.

**Flag:** `r00t{x0r_k3ys_h4t3_kn0wn_pl41nt3xt}`

## TL;DR

- The capture is mostly normal HTTPS, DNS and NTP noise from about 35 hosts.
- One host, `10.60.4.112`, opens a TCP session to `91.242.87.19:4444`, the only non-443 TCP destination in the file.
- It sends four ~33-byte binary messages roughly 2 seconds apart. That is a beacon.
- The payload is XOR-encrypted with a repeating 6-byte key. Guessing the plaintext word `CHECKIN` recovers the key, and the same key decrypts the server's reply, which contains the flag.

> **Note on tooling:** the commands below are the Kali (`tshark` + `python3`) way of doing each step. While solving, I parsed the pcap with a small raw Python parser. The values, timestamps and bytes shown are the real ones from `beacon.pcap`.

## Step 1: Set up the workspace

Create a working folder, list the archive before extracting it, then extract only the pcap (the `__MACOSX` entry is just macOS metadata).

```
┌──(enos㉿kali)-[~]
└─$ mkdir -p ~/ctf/beacon && cd ~/ctf/beacon

┌──(enos㉿kali)-[~/ctf/beacon]
└─$ cp ~/Downloads/beacon_2_.zip . && unzip -l beacon_2_.zip
Archive:  beacon_2_.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   394684  2026-09-19 19:15   beacon.pcap
      312  2026-09-19 19:15   __MACOSX/._beacon.pcap
---------                     -------
   394996                     2 files

┌──(enos㉿kali)-[~/ctf/beacon]
└─$ unzip -q beacon_2_.zip -x '__MACOSX/*'

┌──(enos㉿kali)-[~/ctf/beacon]
└─$ file beacon.pcap
beacon.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)

┌──(enos㉿kali)-[~/ctf/beacon]
└─$ tshark -r beacon.pcap | wc -l
3696
```

A plain pcap with 3,696 packets. Too many to read by eye, so the plan is to profile the traffic and look for outliers.

## Step 2: Profile the traffic

Start with the services a normal office host would use. First, DNS: which names are being looked up?

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ tshark -r beacon.pcap -Y 'dns.flags.response==0' -T fields -e dns.qry.name | sort | uniq -c | sort -rn
     60 graph.microsoft.com
     53 api.slack.com
     52 fonts.googleapis.com
     52 cdn.jsdelivr.net
     52 zoom.us
     51 update.googleapis.com
     50 github.com
     48 outlook.office365.com
     48 teams.microsoft.com
     42 clients2.google.com
     40 time.windows.com
     38 drive.google.com
     36 docs.google.com
     28 s3.amazonaws.com
```

Only 14 distinct names, 650 queries in total, all legitimate SaaS and CDN domains. Every query is an A record. No DGA-looking names, no long encoded subdomains, so no DNS tunnelling or fast-flux C2 here.

Next, NTP:

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ tshark -r beacon.pcap -Y 'ntp' -T fields -e ip.dst | sort | uniq -c
     60 132.163.97.1
```

Every host syncs time with the same public time server. Benign.

That leaves TCP. The bulk of it is HTTPS on 443, which I can't read, so I look for anything that is not going to 443. I filter on the first packet of each connection (SYN without ACK):

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ tshark -r beacon.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.dstport!=443' -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c
      1 10.60.4.112 91.242.87.19 4444
```

One connection stands out: `10.60.4.112 → 91.242.87.19:4444`. Port 4444 is the classic default for Metasploit handlers and many reverse shells and RATs, it is a public IP, and no other host in the capture talks to it. This is our suspect.

## Step 3: Inspect the suspect session

I check the whole TCP session: handshake, data, and teardown.

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ tshark -r beacon.pcap -Y 'tcp.port==4444' -T fields -e frame.time_epoch -e ip.src -e tcp.flags -e tcp.len
1789838168.942889000    10.60.4.112     0x0002  0
1789838170.175102000    91.242.87.19    0x0012  0
1789838171.247973000    10.60.4.112     0x0010  0
1789838173.221786000    10.60.4.112     0x0018  33
1789838174.856310000    91.242.87.19    0x0010  0
1789838175.017860000    10.60.4.112     0x0018  33
1789838176.611178000    91.242.87.19    0x0010  0
1789838177.311641000    10.60.4.112     0x0018  33
1789838178.502548000    91.242.87.19    0x0010  0
1789838179.489910000    10.60.4.112     0x0018  35
1789838180.758900000    91.242.87.19    0x0010  0
1789838180.948377000    91.242.87.19    0x0018  44
1789838181.868358000    10.60.4.112     0x0010  0
1789838182.427243000    10.60.4.112     0x0011  0
1789838183.433849000    91.242.87.19    0x0011  0
1789838184.066365000    10.60.4.112     0x0010  0
```

Reading the flags: `0x02` SYN, `0x12` SYN-ACK, `0x10` ACK, `0x18` PSH-ACK (data), `0x11` FIN-ACK. So it is a full, normal TCP session with five data packets:

- four from the client (33, 33, 33 and 35 bytes), roughly every 2 seconds,
- one from the server (44 bytes) that arrives right after the fourth client message.

The gaps between the client messages are 1.80 s, 2.29 s and 2.18 s, which is a ~2 s interval with a little jitter. Regular, small, repeated messages from the same host to the same remote service is the textbook definition of a beacon (check-in).

Now I pull the payload bytes out into a file, one message per line:

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ tshark -r beacon.pcap -Y 'tcp.port==4444 && tcp.len>0' -T fields -e tcp.payload | tr -d ':' | tee payloads.txt
74ea11a08c4b79983c8cb4761a9563d0f338069563d3f732079264d3fd6b53ce31
74ea11a08c4b79983c8cb4761a9563d0f338069563d3f732079262d3fd6b53ce31
74ea11a08c4b79983c8cb4761a9563d0f338069563d3f732079366d3fd6b53ce31
74ea11a08c4b79983c8cb4761a9563d0f338069563d3f73207936cd3fd6354d63d95a2
63e307a8fd6354c96e91f73243d92cd3b55d5c912d90986a03d667bcac6c07d53abcb76e03933a97f47a43df
```

Lines 1-4 are the client check-ins, line 5 is the server's answer.

## Step 4: Look at the payload

Two quick checks tell me what kind of data this is.

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ head -1 payloads.txt | xxd -r -p | xxd
00000000: 74ea 11a0 8c4b 7998 3c8c b476 1a95 63d0  t....Ky.<..v..c.
00000010: f338 0695 63d3 f732 0792 64d3 fd6b 53ce  .8..c..2..d..kS.
00000020: 31                                       1

┌──(enos㉿kali)-[~/ctf/beacon]
└─$ head -1 payloads.txt | xxd -r -p | strings -n 4

┌──(enos㉿kali)-[~/ctf/beacon]
└─$
```

`strings` finds nothing, so it isn't plain text. Now let me compare the four client messages with each other (using a quick Python one-liner):

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ python3 -c "
m=[bytes.fromhex(l) for l in open('payloads.txt').read().split()]
for n in (1,2,3):
    print('msg1 vs msg%d differing offsets:'%(n+1), [i for i in range(33) if m[0][i]!=m[n][i]])
"
msg1 vs msg2 differing offsets: [26]
msg1 vs msg3 differing offsets: [25, 26]
msg1 vs msg4 differing offsets: [25, 26, 29, 30, 31, 32]
```

What this tells me:

- Messages 1-3 are identical except for one or two bytes at offsets 25-26. That looks like a counter or timestamp changing inside an otherwise fixed message.
- If a strong cipher (AES, ChaCha) with a fresh nonce were used, every byte would change between messages. Here, a one-character change in the plaintext changes exactly one byte of ciphertext. That is the signature of a stream-style cipher with a fixed key stream, most likely a plain XOR with a static key.
- Message 4 is 2 bytes longer and differs at the end, so the last field changed (a different status word).

## Step 5: Find the XOR key length

With a repeating-key XOR, two ciphertext bytes that are key length apart are encrypted with the same key byte. So `c[i] ^ c[i+L]` equals `p[i] ^ p[i+L]`, which is a small value whenever the plaintext repeats similar characters (digits, separators, repeated letters). The key length `L` is the one that gives lots of small XORs.

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ python3 -c "
p=bytes.fromhex(open('payloads.txt').readline().strip())
for L in range(1,13):
    print('L=%-2d small-xors=%d' % (L, sum(1 for i in range(len(p)-L) if p[i]^p[i+L] < 0x10)))
"
L=1  small-xors=0
L=2  small-xors=0
L=3  small-xors=1
L=4  small-xors=0
L=5  small-xors=2
L=6  small-xors=12
L=7  small-xors=0
L=8  small-xors=0
L=9  small-xors=3
L=10 small-xors=1
L=11 small-xors=1
L=12 small-xors=5
```

`L=6` is a clear spike (and `L=12` is its multiple). The key is **6 bytes** long. The server's reply shows the same pattern at `L=6`, which suggests both directions use the same key.

## Step 6: Recover the key with a known-plaintext (crib) attack

A 6-byte key means that if I can guess just six consecutive plaintext characters, I can recover the whole key (`key[i] = cipher[i] ^ plain[i]`).

A beacon's first message is very likely to start with something like `HELLO`, `BEACON`, `PING` or `CHECKIN`. To avoid guessing blindly, I first work out which byte values are possible at each key position. The correct key must turn every byte at that position into printable ASCII, in all five messages. Then I slide each candidate crib along the messages and keep only the placements where the implied key bytes fall inside those allowed sets.

The crib `CHECKIN` at offset 0 survives and gives a full key. It was also confirmed independently by another crib, `host=`, which implies the same bytes at key positions 2-5:

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ python3 -c "
p=bytes.fromhex(open('payloads.txt').readline().strip())
crib=b'CHECKIN'
print(' '.join('%02x' % (p[i]^crib[i]) for i in range(len(crib))))
"
37 a2 54 e3 c7 02 37
```

The 7th byte (`37`) equals the 1st, which is exactly what a 6-byte repeating key must do. That repeat is a good consistency check.

**Recovered key:** `37 a2 54 e3 c7 02`

## Step 7: Decrypt everything

Here is the final solver:

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ cat solve.py
#!/usr/bin/env python3
key = bytes.fromhex('37a254e3c702')
for line in open('payloads.txt').read().split():
    c = bytes.fromhex(line)
    print(bytes(b ^ key[i % len(key)] for i, b in enumerate(c)).decode())

┌──(enos㉿kali)-[~/ctf/beacon]
└─$ python3 solve.py
CHECKIN:host-7734:1770000000:idle
CHECKIN:host-7734:1770000060:idle
CHECKIN:host-7734:1770000120:idle
CHECKIN:host-7734:1770000180:active
TASK:ack:r00t{x0r_k3ys_h4t3_kn0wn_pl41nt3xt}
```

It decodes cleanly, including the server's reply, so the key is right.

What each message means:

| # | Direction | Plaintext | Meaning |
|---|-----------|-----------|---------|
| 1 | Host → C2 | `CHECKIN:host-7734:1770000000:idle` | Bot ID `host-7734`, timestamp, state idle |
| 2 | Host → C2 | `CHECKIN:host-7734:1770000060:idle` | Timestamp +60, still idle |
| 3 | Host → C2 | `CHECKIN:host-7734:1770000120:idle` | Timestamp +60, still idle |
| 4 | Host → C2 | `CHECKIN:host-7734:1770000180:active` | State changes to active (explains the 2 extra bytes) |
| 5 | C2 → Host | `TASK:ack:r00t{...}` | The C2 acknowledges and replies with the flag |

This also explains the earlier byte-diff results: the changing bytes at offsets 25-26 were the last two digits of the timestamp, and message 4 differs at the end because `idle` became `active`.

## Step 8: Flag

```
┌──(enos㉿kali)-[~/ctf/beacon]
└─$ python3 solve.py | tail -1 | grep -o 'r00t{.*}'
r00t{x0r_k3ys_h4t3_kn0wn_pl41nt3xt}
```

**Flag:** `r00t{x0r_k3ys_h4t3_kn0wn_pl41nt3xt}`

## Indicators of compromise (IOCs)

| Type | Value |
|------|-------|
| Infected host | `10.60.4.112` |
| C2 server | `91.242.87.19:4444/tcp` |
| Bot ID | `host-7734` |
| Beacon interval | ~2 s between messages, jittered |
| Message format | `CHECKIN:<id>:<timestamp>:<state>` |
| Encryption | Repeating-key XOR, key `37a254e3c702` |

## What I learned

1. **Beacons are about patterns, not content.** You can spot one without decrypting anything: small messages, same destination, regular timing, from one host. In a large capture, look for the outlier (here, the only non-443 destination).
2. **Baseline first, then hunt outliers.** Ruling out DNS (14 benign names), NTP (one public time server) and the 443 noise made the single odd connection obvious.
3. **Unusual ports are a cheap but effective signal.** Port 4444 is a default for Metasploit and many RATs. It should never be talking to a public IP from an office network.
4. **Handle "encrypted-looking" data with structure analysis.** If one changed character in the plaintext changes exactly one ciphertext byte, you are dealing with XOR or a reused key stream, not real encryption.
5. **Repeating-key XOR falls to two classic tricks:** find the key length by looking at how often bytes `L` apart XOR to small values, then recover the key with a known-plaintext crib. Protocol words like `CHECKIN`, `HELLO`, `BEACON` and `host=` are great cribs.
6. **Never reuse a key stream.** Because the same key was used for every message and both directions, one correct guess decrypted the entire conversation. Real malware that uses XOR is trivially breakable once a single sample is captured.
7. **Check the other side too.** The flag was in the server's reply, not in the beacons. Always decode both directions of a session.

## Defender notes

- Alert on outbound connections to uncommon ports (4444, 1337, 31337, 8080 to raw IPs) from workstations.
- Detect beaconing statistically: low variance in inter-packet times and message sizes to a single destination (tools such as RITA or Zeek-based beacon analysis).
- Block or at least log egress to destinations that are not in your DNS history. Here the C2 was a bare IP with no preceding DNS lookup.
- Isolate `10.60.4.112`, capture memory, and look for the process that opened the connection from source port `39281`.
