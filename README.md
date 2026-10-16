# simple-pac-file

Extract the `FindProxyForURL` function and the standard PAC DNS helper calls it makes from a PAC (Proxy Auto-Configuration) file's text, for offline inspection without executing JavaScript.

```python
from simple_pac_file import PacFile, PacParseError
from simple_pac_file.core import parse_pac

text = "function FindProxyForURL(url, host) { return 'DIRECT'; }"
pac = parse_pac(text)
print(pac.find_proxy_for_url)  # exact source slice of the function
print(pac.dns_helpers)         # e.g. ['dnsResolve', 'isInNet']
```

## Why this exists

PAC files decide which proxy a browser uses for each URL. They are plain JavaScript defining `FindProxyForURL(url, host)`, but to audit one you usually have to run it or hand-read the whole file. This library pulls out just the decision function and the DNS helper names it calls, so you can inspect policy without a JS engine or network access.

The trade-off: the parser is lexical, not a full JavaScript grammar. It tracks string literals, line and block comments, and brace depth to locate the function and detect bareword calls like `dnsResolve(`. It will not evaluate expressions or resolve hostnames. It detects calls to the standard PAC DNS helpers (`dnsResolve`, `isResolvable`, `isInNet`, `dnsDomainIs`, `localHostOrDomainIs`); it does not detect arbitrary custom helpers or dotted member calls like `foo.dnsResolve(`.

## Edge you will hit

If the PAC file has no top-level `FindProxyForURL`, `parse_pac` raises `PacParseError`. A function nested inside another function is not mistaken for the top-level one, but its body is part of the outer function's extracted text. The extracted source is the exact character slice from `function` to the matching closing brace; indentation and surrounding whitespace are preserved as written.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

