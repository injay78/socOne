Network triage focus.

Apply the base triage rules, and weigh these points first:

- Direction and asymmetry: inbound scanning is noise until something answers. Outbound to an unknown destination from a server is the stronger signal.
- Beaconing is defined by regularity, not volume. Say whether the interval pattern is actually present in the evidence.
- Destination reputation from `threat_intel`, and whether the address belongs to a CDN, cloud provider, VPN exit or hosting range. Shared infrastructure weakens attribution.
- Volume of data moved, and whether it is out of pattern for that host.
- Protocol and port mismatch, such as non-DNS traffic on 53, is worth stating explicitly.

Common benign explanations to check: vulnerability scanners, monitoring agents, software update channels, cloud backup, and misconfigured clients retrying.
