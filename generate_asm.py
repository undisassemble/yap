# This turns the assembly sources into headers that can be used by the packer, to make it easier to read/modify the packers shellcode
# 
# Special commands:
#     %ifdef condition                      Same as C #ifdef, end with %endif
#     %ifndef condition                     Same as C #ifndef, end with %endif
#     %if condition                         Wraps code in an if statement, condition should be c-style
#     %elif condition                       Else if statement
#     %else                                 Else statement
#     %endif                                Ends if statement
#     %define                               Same as #define
#     %undef                                Same as #undef
#     %include                              Include file
#     ; GLOBAL                              Following label is global, and should not be created
#     ; RAW_C line                          line is C code that should be embedded in the source
# 
# Some defines have special meanings:
#     ASSEMBLER <asm>                       Prefix for instructions
# 
# These comments should have their own lines, any comments following source will be ignored.
# Also, custom instructions like strict or embed work

import math, os

# Change as needed
IN_DIR = "./YAP/src/modules/"
OUT_DIR = "./YAP/include/modules/"

# Defined by source
ASSEMBLER = ""

# Dont change
IfStack = []
NeededLabels = []
BoundLabels = []
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
Prefixes = [
    "lock",
	"rep",
	"repe",
	"repne",
	"repz",
	"repnz",
	"xrelease",
	"xacquire"
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

    # Make sure elements are correct
    i = 0
    n = elements.__len__()
    while i < n:
        if (elements[i].count('[') > elements[i].count(']')) or (elements[i].count('{') > elements[i].count('}')) or (elements[i].count('(') > elements[i].count(')')) or (elements[i].count('"') % 2) or (elements[i].count('\'') % 2):
            if i == n - 1:
                raise Exception("Unmatched opening parentheses")
            elements[i] += '+' + elements[i + 1]
            del elements[i + 1]
            n -= 1
            continue
        i += 1
    
    for element in elements:
        element = element.strip()

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
            if element.startswith("offsetof") or element.startswith("sizeof"):
                noff = element
            else:
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
    global GlobalLabel, IfStack, NeededLabels, BoundLabels, ValidRegs, ASSEMBLER
    line = line.strip()
    if not line or line == '':
        return ""

    # Parse comments
    if line[0] == ';':
        line = line[1:].strip()
        if line.startswith("GLOBAL"):
            GlobalLabel = True
            return ""
        elif line.startswith("RAW_C "):
            return line.split("RAW_C ")[1] + "\n"
        else:
            return ""

    # Special stuff
    elif line[0] == '%':
        if line.lower().startswith("%if "):
            IfStack.append(1)
            return "if (" + line[4:] + ") {\n"
        elif line.lower().startswith("%elif "):
            if IfStack.__len__() < 1:
                raise Exception("ELIF when not in an if statement")
            if IfStack[-1]:
                return "} else if (" + line[6:] + ") {\n"
            else:
                return "#elif " + line[6:] + "\n"
        elif line.lower().startswith("%else"):
            if IfStack.__len__() < 1:
                raise Exception("ELSE when not in an if statement")
            if IfStack[-1]:
                return "} else {\n"
            else:
                return "#else\n"
        elif line.lower().startswith("%ifdef "):
            IfStack.append(0)
            return "#if defined(" + line[7:] + ")\n"
        elif line.lower().startswith("%ifndef "):
            IfStack.append(0)
            return "#if !defined(" + line[8:] + ")\n"
        elif line.lower().startswith("%endif"):
            if IfStack.__len__() < 1:
                raise Exception("ENDIF when not in an if statement")
            if IfStack.pop():
                return "}\n"
            else:
                return "#endif\n"
        elif line.lower().startswith("%include "):
            return "#include " + line[9:] + "\n"
        elif line.lower().startswith("%define "):
            if line[8:].strip().startswith("ASSEMBLER "):
                ASSEMBLER = line[8:].strip()[10:].strip()
            else:
                return "#define " + line[8:] + "\n"
        elif line.lower().startswith("%undef "):
            return "#undef " + line[7:] + "\n"


    # Parse line
    else:
        toret = ""
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
            return f"{ASSEMBLER}bind(" + line[:-1] + ");\n"

        # Instructions without operands
        if line.count(' ') == 0:
            return f"{ASSEMBLER}{line}();\n"

        # Prefixes
        while line.split(' ')[0].lower() in Prefixes:
            toret += ASSEMBLER + line.split(' ')[0].lower() + "();\n"
            line = ' '.join(line.split(' ')[1:])

        mnem = line.split(' ')[0].lower()
        ops = line[mnem.__len__() + 1:].split(',')
        
        # Make sure operands are correct
        i = 0
        n = ops.__len__()
        while i < n:
            if (ops[i].count('[') > ops[i].count(']')) or (ops[i].count('{') > ops[i].count('}')) or (ops[i].count('(') > ops[i].count(')')) or (ops[i].count('"') % 2) or (ops[i].count('\'') % 2):
                if i == n - 1:
                    raise Exception("Unmatched opening parentheses")
                ops[i] += ',' + ops[i + 1]
                del ops[i + 1]
                n -= 1
                continue
            i += 1

        # Write mnemonic + prefixes
        l = mnem.split(' ')
        for i in range(l.__len__() - 1):
            toret += f"{ASSEMBLER}{l[i]}();\n"
        if l[-1] in MnemonicConversions:
            toret += f"{ASSEMBLER}{MnemonicConversions[l[-1]]}("
        else:
            toret += f"{ASSEMBLER}{l[-1]}("
        del l

        first = True
        for operand in ops:
            if not first:
                toret += ", "
            first = False
            operand = operand.strip()

            # Only memory operands need to be parsed
            if operand[0] == '[' or (operand.count(' ') > 0 and operand.split(' ')[1][0] == '['):
                toret += parse_mem(operand)
            else:
                toret += operand

        toret += ");\n"
        return toret


def main():
    global GlobalLabel, IfStack, NeededLabels, BoundLabels, ValidRegs, ASSEMBLER
    for fname in os.listdir(IN_DIR):
        if not fname.lower().endswith(".asm"):
            continue

        # Clear vars
        NeededLabels = []
        BoundLabels = []
        IfStack = []
        GlobalLabel = False
        infile = None
        outfile = None
        ASSEMBLER = ""

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
            outfile.write(f"Label {label} = {ASSEMBLER}newLabel();\n")

        # Write stuff
        for line in parsed:
            if line:
                outfile.write(line)
        outfile.write("}")
        outfile.close()
        infile.close()

if __name__ == "__main__":
    if not os.path.isdir(OUT_DIR):
        os.mkdir(OUT_DIR)
    main()