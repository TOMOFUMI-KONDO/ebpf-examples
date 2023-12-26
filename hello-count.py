#!/usr/bin/python3

from time import sleep
from bcc import BPF


program = r"""
BPF_HASH(counter_table);

static int count_up(u64 uid) {
    u64 counter = 0;
    u64 *p;

    p = counter_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table.update(&uid, &counter);

    return 0;

}

int hello(void *ctx) {
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    count_up(uid);

    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(1)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
