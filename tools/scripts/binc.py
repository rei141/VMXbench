import sys
import os
input_file = sys.argv[1]
header_file = sys.argv[2]
source_file = sys.argv[3]

with open(input_file, 'rb') as f:
    data = f.read()

# ヘッダファイルを生成
with open(header_file, 'w') as f:
    f.write('#ifndef BINARY_DATA_H\n')
    f.write('#define BINARY_DATA_H\n\n')
    f.write(f'#define BINARY_DATA_SIZE {len(data)}\n\n')
    f.write('extern unsigned char binary_data[BINARY_DATA_SIZE];\n\n')
    f.write('#endif // BINARY_DATA_H\n')

# ソースファイルを生成
with open(source_file, 'w') as f:
    f.write(f'#include "{os.path.basename(header_file)}"\n\n')
    f.write('unsigned char binary_data[] = {\n')
    f.write(','.join(f'0x{byte:02x}' for byte in data))
    f.write('\n};\n')