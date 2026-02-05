EgressLens will observe outbound network activity for a command run inside a controlled Linux environment. 

It runs your command, traces network syscalls with strace, and parses connect/send events into JSONL for analysis. 

JSONL can then be explored in web UI to see top destinations, timelines, potentially exportable reports, and the like.

The idea is to run a tool/script/app, capture what it talks to, shutdown, and then analyze.

