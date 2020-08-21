# Crude HTLC-Contract implementation for CKB in C

Everything in the `deps` folder can potentially be outsourced to other cells and dynamically loaded within the contract.
This would safe precious `CKBytes`. Having it statically linked like this leads to a binary size of **14778 Bytes**.