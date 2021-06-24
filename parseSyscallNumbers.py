#!/usr/bin/env python
import json

if __name__ == '__main__':
    with open('./syscalls.txt') as fd:
        syscalls = fd.readlines()

syscallMap = {}
for line in syscalls:
    if "#define" in line:
        start = line.rfind('_')
        end = line.rfind(' ')
        syscall = line[start + 1:end]
        number = (line[end:])
        if len(syscall) > 0 and len(number) > 0 and syscall != 'SYSCALL(x,':
            number = hex(int(number))
            syscallMap[number] = {
                "name": syscall,
                "number": number
            }

print(json.dumps(syscallMap))