import sys
while word := sys.stdin.buffer.read(4):
    sys.stdout.buffer.write(bytes(reversed(word)))
