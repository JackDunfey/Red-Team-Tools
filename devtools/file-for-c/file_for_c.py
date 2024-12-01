import argparse
# Simple version 0.1.2
if __name__ != "__main__":
    raise Exception("This should not be included")



parser = argparse.ArgumentParser(
    prog='file_for_c',
    description='Reads a file into a notation ready to be read by a C program',
    epilog=''
)
parser.add_argument('input_file')
parser.add_argument('-o', '--output')
# parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")

args = parser.parse_args()



from json import dumps
out_lines = []
with open(args.input_file, 'r') as f:
    for line in f.readlines():
        line = dumps(line)
        print(line)
#         out_lines.append(f'"{line}"')
# for line in out_lines:
#     print(line)