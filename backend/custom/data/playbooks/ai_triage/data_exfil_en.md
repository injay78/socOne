Data movement triage focus.

Apply the base triage rules, and weigh these points first:

- Was data actually transferred, or only accessed or staged? These are different stages and different severities.
- Volume relative to that user's and that host's normal pattern, not an absolute threshold.
- Destination: sanctioned corporate storage, personal cloud storage, external mail, or unknown infrastructure.
- Data classification from `cmdb` where available. Movement of customer or payment data changes impact regardless of volume.
- Timing relative to employment events when `identity` shows them, such as a recently disabled or notice-period account.

Common benign explanations to check: approved backup jobs, data migration projects, business reporting exports, and developer syncing to sanctioned storage.
