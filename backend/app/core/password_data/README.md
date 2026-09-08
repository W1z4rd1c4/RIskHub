# Offline common-password policy data

`common-passwords.txt` is the unmodified SecLists 10k common-credential list at
commit `3153474db3a882d4410aa4f4f0ac300cca0fee0e`; `manifest.json` records its pinned
source and SHA-256. `LICENSE` retains the upstream MIT attribution.

This is a bounded denylist, not an exhaustive compromised-password corpus. Native
credential setting also enforces the 15–128-character policy and supports an
operator-supplied additional list. Runtime never queries an external password API.

Updating this input requires source/license review, a new checksum and policy
regressions, then a rebuilt immutable artifact. A checksum mismatch fails closed.
