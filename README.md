# angry-FSROP
a new class of file structure attacks

# How to Use
Run the following command: `python angry-fsrop.py`.
Then it will start analyzing glibc-2.35, which comes with the repo.

# Verify a Technique
Use the following script to see the trace of a symbolic state and manually verify the feasibility by reading the disassembly.
```
import pickle
with open("./outputs/_IO_wfile_overflow.pickle", 'rb') as f:
    states = pickle.load(f)
for x in states[0].history.bbl_addrs:
    print(hex(x))
```
