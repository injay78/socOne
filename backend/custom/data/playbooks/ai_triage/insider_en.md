Insider and privilege triage focus.

Apply the base triage rules, and weigh these points first:

- Authorisation, not capability: the question is whether this account was supposed to do this, which `identity` and `cmdb` help answer.
- Privilege changes: group membership, role assignment, policy modification. Who granted it, and was it self-granted.
- Access outside the account's normal scope: systems, data, or hours the role does not usually touch.
- Sequence matters more than any single event. Privilege grant followed by access followed by data movement is a chain; any one alone often is not.
- Deliberate concealment such as log clearing, audit disabling or rule modification raises severity sharply.

Handle with care: an insider verdict has consequences for a real employee. Prefer `needs_more_info` over an unsupported accusation, and state plainly what evidence would settle it.
