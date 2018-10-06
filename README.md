# A Linux kernel module that logs the activity of Valve Anti-Cheat

This module hooks system calls and looks for activity of VAC on a target process. Target process is defined by writing to the vaclog entry in procfs.

Compile with make and then simply insmod the module.
