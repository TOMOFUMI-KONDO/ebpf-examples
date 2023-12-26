#!/usr/bin/python3

from time import sleep
from bcc import BPF

program = r"""
BPF_HASH(counter_table);

static int count_up() {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table.update(&uid, &counter);

    return 0;

}

int hello_openat(void *ctx) {
    bpf_trace_printk("openat");
    count_up();

    return 0;
}

int hello_write(void *ctx) {
    bpf_trace_printk("write");
    count_up();

    return 0;
}
"""

b = BPF(text=program)
openat = b.get_syscall_fnname("openat")
b.attach_kprobe(event=openat, fn_name="hello_openat")

write = b.get_syscall_fnname("write")
b.attach_kprobe(event=write, fn_name="hello_write")

while True:
    sleep(1)
    line = b.trace_readline(nonblocking=False)
    print(line)

    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)
