#!/usr/bin/python3

from time import sleep
from bcc import BPF

program = r"""
BPF_HASH(counter_table);

static int count_up(u64 opcode) {
    u64 counter = 0;
    u64 *p;

    p = counter_table.lookup(&opcode);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table.update(&opcode, &counter);

    return 0;

}

int hello(struct bpf_raw_tracepoint_args *ctx) {
    u64 opcode = ctx->args[1] & 0xFFFFFFFF;
    count_up(opcode);

    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

while True:
    sleep(1)

    kv = []
    for k, v in b["counter_table"].items():
        kv.append([k.value, v.value])

    kv.sort(key=lambda x: x[1], reverse=True)

    s = ""
    for i in range(len(kv)):
        s += f"OPCODE {kv[i][0]}: {kv[i][1]}\t"
    s += "\n"
    print(s)
