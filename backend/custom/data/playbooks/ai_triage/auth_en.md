Authentication and identity triage focus.

Apply the base triage rules, and weigh these points first:

- Did the authentication actually succeed? A failed brute-force burst and a successful login after it are very different verdicts.
- Source of the attempt: internal subnet, VPN pool, known jump host, or external address. Correlate with `cmdb` and `identity`.
- Account type: service account, privileged account, or ordinary user. A service account authenticating from a workstation is more interesting than volume alone.
- Volume and rhythm: password spraying is wide and shallow, brute force is narrow and deep, a misconfigured client retries in a fixed pattern.
- Impossible travel and time-of-day only matter when the account's normal pattern is known. Say so when it is not.
- A locked-out account with no successful login is usually not a compromise. Do not raise severity on failure volume alone.

Common benign explanations to check before calling true positive: expired credentials on a scheduled task, a scanner in the security test range, a shared account after a password rotation.
