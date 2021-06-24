Tiny frida script to parse system calls by using Stalker and checking for `svc`. Based off https://github.com/sh1ma/iostrace/blob/master/src/tracer.js

Uses some code from frida as well https://github.com/frida/frida-tools/tree/f772d2ee692165a5f6a1d2e4fdf3c9798c2a654d


`main.py` will trace the specified package name and generate JSON output in `/tmp/x.json`, `report.py` will generate `/tmp/x.html` based off the JSON file.

This is buggy and I'm working on something better.