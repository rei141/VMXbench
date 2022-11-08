path = input()
with open(path) as f:
    for s_line in f:
        # print(int(s_line.strip(),16)-1)
        print(hex(int(s_line.strip(),16)-5))