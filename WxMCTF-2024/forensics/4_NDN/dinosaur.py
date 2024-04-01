import sys
with open("dino", "rb") as dino, open("saur", "rb") as saur:
	while True:
		sys.stdout.buffer.write(dino.read(2))
		sys.stdout.buffer.write(saur.read(2))