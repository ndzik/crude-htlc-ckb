# Crude HTLC-Contract implementation for CKB in C

**WARNING/DISCLAIMER:** This implementation is untested and should not be relied upon or even considered to be used with real funds in a real scenario.

Everything in the `deps` folder can potentially be outsourced to other cells and dynamically loaded within the contract.
This would safe precious `CKBytes`. Having it statically linked like this leads to a binary size of **14778 Bytes**.