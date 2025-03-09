# This turns the assembly sources into headers that can be used by the packer, to make it easier to read/modify the packers shellcode

# Some comments in asm sources are treated specially, these are:
#     ; IMPORT label1, label2, ...          Import labels from outside code (already bound)
#     ; GLOBAL                              Following label is global, and should not be created (not already bound)
#     ; IF condition                        Wraps code in an if statement, condition should be c-style
#     ; ENDIF                               Ends if statement
#     ; DEBUG_ONLY                          Following code only present in debug builds
#     ; RELEASE_ONLY                        Following code only present in release builds
#     ; ENDONLY                             Ends DEBUG_ONLY and RELEASE_ONLY segments
#     ; RAW_C line                          line is C code that should be embedded in the source
# These comments should have their own lines, any comments following source will be ignored.
# Also, strict is considered an instruction

import math

# Change as needed
IN_DIR = "./YAP/src/modules/"
OUT_DIR = "./YAP/include/modules/"
SOURCES = [
    
]

# Dont change
NeededLabels = []
BoundLabels = []
NumIfs = 0
GlobalLabel = False
MnemonicConversions = {
    'xor': 'xor_',
    'not': 'not_',
    'and': 'and_',
    'or':  'or_',
}
ValidRegs = [
    "rax",   "eax",   "ax",   "al", "ah",
    "rbx",   "ebx",   "bx",   "bl", "bh",
    "rcx",   "ecx",   "cx",   "cl", "ch",
    "rdx",   "edx",   "dx",   "dl", "dh",
    "rsi",   "esi",   "si",   "sil",
    "rdi",   "edi",   "di",   "dil",
    "rbp",   "ebp",   "bp",   "bpl",
    "rsp",   "esp",   "sp",   "spl",
    "r8",    "r8d",   "r8w",  "r8b",
    "r9",    "r9d",   "r9w",  "r9b",
    "r10",   "r10d",  "r10w", "r10b",
    "r11",   "r11d",  "r11w", "r11b",
    "r12",   "r12d",  "r12w", "r12b",
    "r13",   "r13d",  "r13w", "r13b",
    "r14",   "r14d",  "r14w", "r14b",
    "r15",   "r15d",  "r15w", "r15b",
    "rip",   "eip",
    "zmm0",  "ymm0",  "xmm0",
    "zmm1",  "ymm1",  "xmm1",
    "zmm2",  "ymm2",  "xmm2",
    "zmm3",  "ymm3",  "xmm3",
    "zmm4",  "ymm4",  "xmm4",
    "zmm5",  "ymm5",  "xmm5",
    "zmm6",  "ymm6",  "xmm6",
    "zmm7",  "ymm7",  "xmm7",
    "zmm8",  "ymm8",  "xmm8",
    "zmm9",  "ymm9",  "xmm9",
    "zmm10", "ymm10", "xmm10",
    "zmm11", "ymm11", "xmm11",
    "zmm12", "ymm12", "xmm12",
    "zmm13", "ymm13", "xmm13",
    "zmm14", "ymm14", "xmm14",
    "zmm15", "ymm15", "xmm15",
    "zmm16", "ymm16", "xmm16",
    "zmm17", "ymm17", "xmm17",
    "zmm18", "ymm18", "xmm18",
    "zmm19", "ymm19", "xmm19",
    "zmm20", "ymm20", "xmm20",
    "zmm21", "ymm21", "xmm21",
    "zmm22", "ymm22", "xmm22",
    "zmm23", "ymm23", "xmm23",
    "zmm24", "ymm24", "xmm24",
    "zmm25", "ymm25", "xmm25",
    "zmm26", "ymm26", "xmm26",
    "zmm27", "ymm27", "xmm27",
    "zmm28", "ymm28", "xmm28",
    "zmm29", "ymm29", "xmm29",
    "zmm30", "ymm30", "xmm30",
    "zmm31", "ymm31", "xmm31",
]

def parse_mem(operand: str) -> str:
    line = ""
    # Size/type
    if operand.lower().split('[')[0].strip():
        line += operand.lower().split('[')[0].strip()
        line += "_"
    line += "ptr("
    
    inner = operand.split('[')[1].split(']')[0].strip()
    elements = inner.split('+')
    base = None
    index = None
    scale = 0
    off = 0
    
    for element in elements:
        element = element.strip()

        # Error checking
        if element.count('-') > 1:
            raise Exception("Too many subtractions in memory operand")
        if element.count('+') > 2:
            raise Exception("Too many additions in memory operand")
        if element.count('*') > 1:
            raise Exception("Too many multiplications in memory operand")

        # Subtracted offset
        if '-' in element:
            if off:
                raise Exception("Too many offsets in memory operand")
            off = -int(element.split('-')[1].strip(), 0)
            element = element.split('-')[0].strip()

        # Index * scale
        if '*' in element:
            if index and not scale and not base:
                base = index
                index = None
            if index or scale:
                raise Exception("Too many indexes in memory operand")
            index = element.split('*')[0].strip()
            scale = int(math.log(int(element.split('*')[1].strip()), 2))
            continue

        # Other stuff
        try:
            noff = int(element, 0)
            if off:
                raise Exception("Too many offsets")
            off = noff
        except ValueError:
            if element.lower() in ValidRegs:
                if not index:
                    index = element.lower()
                elif base:
                    raise Exception("Too many bases/indexes")
                else:
                    base = element.lower()
            elif base:
                raise Exception("Too many bases")
            else:
                base = element

    if not index and not base:
        line += f"{off}"
    elif not base and index and not scale:
        line += f"{index}, {off}"
    elif not base and index:
        line += f"{off}, {index}, {scale}"
    elif base and index:
        line += f"{base}, {index}, {scale}, {off}"
    elif base and not index:
        line += f"{base}, {off}"

    line += ")"
    return line

def parse_line(line: str) -> str:
    global GlobalLabel, NumIfs, NeededLabels, BoundLabels, ValidRegs
    if line == "\n":
        return ""
    line = line.strip()

    # Parse comments
    if line[0] == ';':
        line = line[1:].strip()
        if line.startswith("IMPORT "):
            for imp in line[7:].split(','):
                if imp.strip() in BoundLabels:
                    raise Exception(f"Import {imp.strip()} already bound or imported")
                BoundLabels.append(imp.strip())
            return ""
        elif line.startswith("GLOBAL"):
            GlobalLabel = True
            return ""
        elif line.startswith("IF "):
            NumIfs += 1
            return "if (" + line.split("IF ")[1] + ") {\n"
        elif line.startswith("ENDIF"):
            if NumIfs < 1:
                raise Exception("ENDIF when not in an if statement")
            return "}\n"
        elif line.startswith("DEBUG_ONLY"):
            return "#ifdef _DEBUG\n"
        elif line.startswith("RELEASE_ONLY"):
            return "#ifndef _DEBUG\n"
        elif line.startswith("ENDONLY"):
            return "#endif\n"
        elif line.startswith("RAW_C "):
            return line.split("RAW_C ")[1] + "\n"
        else:
            return ""

    # Parse line
    else:
        line = line.split(';')[0].strip()

        # Error checking
        if line.count('[') > 1:
            raise Exception("Too many memory operands")

        # Label
        if line[-1] == ':':
            if line[:-1] in BoundLabels:
                raise Exception(f"Label {line[:-1]} already bound or imported")
            BoundLabels.append(line[:-1])
            if not GlobalLabel:
                NeededLabels.append(line[:-1])
            GlobalLabel = False
            return "a.bind(" + line[:-1] + ");\n"

        # Instructions without operands
        if line.count(' ') == 0:
            return f"a.{line}();\n"

        mnem = ' '.join(line.split(',')[0].split('[')[0].split(' ')[:-1]).lower()
        ops = line[mnem.__len__() + 1:].split(',')
        
        # Make sure operands are correct
        i = 0
        n = ops.__len__()
        while i < n:
            if (ops[i].count('[') > ops[i].count(']')) or (ops[i].count('{') > ops[i].count('}')) or (ops[i].count('(') > ops[i].count(')')) or (ops[i].count('"') % 2) or (ops[i].count('\'') % 2):
                if i == n - 1:
                    raise Exception("Unmatched opening parentheses")
                ops[i] += ', ' + ops[i + 1]
                del ops[i + 1]
                n -= 1
                continue
            i += 1

        # Write mnemonic + prefixes
        l = mnem.split(' ')
        line = ""
        for i in range(l.__len__() - 1):
            line += f"a.{l[i]}();\n"
        if l[-1] in MnemonicConversions:
            line += f"a.{MnemonicConversions[l[-1]]}("
        else:
            line += f"a.{l[-1]}("
        del l

        first = True
        for operand in ops:
            if not first:
                line += ", "
            first = False
            operand = operand.strip()

            # Only memory operands need to be parsed
            if '[' in operand:
                line += parse_mem(operand)
            else:
                line += operand

        line += ");\n"
    
    return line


def main():
    global GlobalLabel, NumIfs, NeededLabels, BoundLabels, ValidRegs
    for fname in SOURCES:
        # Clear vars
        NeededLabels = []
        BoundLabels = []
        NumIfs = 0
        GlobalLabel = False
        infile = None
        outfile = None

        # Open file
        try:
            infile = open(IN_DIR + fname, 'r')
            outfile = open(OUT_DIR + fname.replace(".asm", ".inc"), 'w')
        except FileNotFoundError:
            print(f"Could not read source {fname}")
            return

        # Prepend stuff
        outfile.write("// This file is auto-generated, do not touch it!\n// Also, don't commit it\n{\n")

        # Parse lines
        parsed = []
        for line in infile.readlines():
            try:
                parsed.append(parse_line(line))
            except Exception as e:
                print(f"Fatal error in line number {parsed.__len__() + 1} in file {fname}: {e}")
                return

        # Define labels
        for label in NeededLabels:
            outfile.write(f"Label {label} = a.newLabel();\n")

        # Write stuff
        for line in parsed:
            outfile.write(line)
        outfile.write("}")
        outfile.close()
        infile.close()

if __name__ == "__main__":
    main()