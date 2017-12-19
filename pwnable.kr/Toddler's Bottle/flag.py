import os

os.system("upx -d flag")  # rely on upx
os.system("echo 'x /s flag \n quit' >> file")
os.system("gdb flag -x file && rm file && rm .gdb_history")

# UPX...? sounds like a delivery service :)
