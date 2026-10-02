# Reference Guide for Claude Code
This document contains the necessary information about the project that will allow Claude Code to help with the project.

# Important Files and Folders
1. `QPASE_Quantum-Resistant_Password-Authenticated_Searchable_Encryption_for_Cloud_Storage.pdf` - This is the paper we are planning to implement
2. `src/` - This is the directory where all the important methods and functions are to be defined. This folder should contain things like abstract classes for entities, for instance User, Server, Attacker, etc and also important functions that are very commonly used, so like all the functions defined in the preliminaries section of the paper like TOPRF, HKDF, etc
3. `notebooks/` - This should contain only .ipynb files that are useful for demonstration. The .ipynb files should reference the functions defined in the `src/` directory and use the functions from there. It should not contain any new implementation of any important functions. It should only show the utility and how the parties are communicating and with what data.
4. `docs/implementation-plan.md` - This file contains the detailed implementation plan.

# Tech Stack
The programming language is python. Package management is maintained by uv.

# Other instructions
1. You are not allowed to install any kind of software. If installation is necessary, you stop and tell me what to install. Even simple `uv add` instructions are not allowed.
2. Anytime a numeric claim is made, it should be referenced in README.md with the file and the cell number that indicates which cell the numeric claim was made from. I want to run that cell again to verify the claims.