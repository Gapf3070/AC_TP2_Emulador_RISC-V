# Gabriel Almeida de Paula Fonseca
# 22450084

import sys
import re


# MAPEAMENTO ABI DE REGISTRADORES

ABI_MAP = {
    "zero": "x0", "ra": "x1", "sp": "x2", "gp": "x3",
    "tp": "x4", "t0": "x5", "t1": "x6", "t2": "x7",
    "s0": "x8", "fp": "x8", "s1": "x9", "a0": "x10", "a1": "x11",
    "a2": "x12", "a3": "x13", "a4": "x14", "a5": "x15",
    "a6": "x16", "a7": "x17", "s2": "x18", "s3": "x19",
    "s4": "x20", "s5": "x21", "s6": "x22", "s7": "x23",
    "s8": "x24", "s9": "x25", "s10": "x26", "s11": "x27",
    "t3": "x28", "t4": "x29", "t5": "x30", "t6": "x31",
}

def parse_reg(reg_str):
    """Converte nome ABI ou numérico para o formato canônico 'x0'...'x31'."""
    reg_str = reg_str.strip().lower()
    if reg_str in ABI_MAP:
        return ABI_MAP[reg_str]
    if reg_str.startswith("x") and reg_str[1:].isdigit():
        val = int(reg_str[1:])
        if 0 <= val <= 31:
            return f"x{val}"
    raise ValueError(f"Registrador inválido: '{reg_str}'")


# FUNÇÕES DE ARITMÉTICA E CONVERSÃO DE 32 BITS

def to_int32(val):
    """Garante que o inteiro em Python fique no intervalo [-2^31, 2^31 - 1]."""
    val = val & 0xFFFFFFFF
    if val >= 0x80000000:
        val -= 0x100000000
    return val

def to_uint32(val):
    """Garante que o valor seja tratado como não sinalizado de 32 bits."""
    return val & 0xFFFFFFFF

def parse_int(val_str):
    """Converte uma string numérica (dec, hex, bin, oct) para inteiro."""
    return int(val_str.strip(), 0)

def parse_mem_operand(op_str):
    """
    Decodifica operandos de memória no formato offset(reg) ou (reg).
    Retorna (offset_inteiro, reg_canonico).
    """
    op_str = op_str.strip()
    m = re.match(r"^\s*([+-]?(?:0x[0-9a-fA-F]+|\d+))?\s*\(\s*([^()]+)\s*\)\s*$", op_str)
    if m:
        offset_str = m.group(1)
        reg_str = m.group(2).strip()
        offset = parse_int(offset_str) if offset_str else 0
        return offset, parse_reg(reg_str)
    raise ValueError(f"Formato de memória inválido: '{op_str}'")


# AUXILIARES DE LEITURA E ESCRITA NA MEMÓRIA

def read_byte_u(memoria, addr):
    return memoria.get(addr, 0) & 0xFF

def read_byte_s(memoria, addr):
    val = read_byte_u(memoria, addr)
    return val - 256 if val >= 0x80 else val

def write_byte(memoria, addr, val):
    memoria[addr] = val & 0xFF

def read_half_u(memoria, addr):
    b0 = read_byte_u(memoria, addr)
    b1 = read_byte_u(memoria, addr + 1)
    return b0 | (b1 << 8)

def read_half_s(memoria, addr):
    val = read_half_u(memoria, addr)
    return val - 0x10000 if val >= 0x8000 else val

def write_half(memoria, addr, val):
    val = val & 0xFFFF
    memoria[addr] = val & 0xFF
    memoria[addr + 1] = (val >> 8) & 0xFF

def read_word_s(memoria, addr):
    b0 = read_byte_u(memoria, addr)
    b1 = read_byte_u(memoria, addr + 1)
    b2 = read_byte_u(memoria, addr + 2)
    b3 = read_byte_u(memoria, addr + 3)
    val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    return to_int32(val)

def write_word(memoria, addr, val):
    val = val & 0xFFFFFFFF
    memoria[addr] = val & 0xFF
    memoria[addr + 1] = (val >> 8) & 0xFF
    memoria[addr + 2] = (val >> 16) & 0xFF
    memoria[addr + 3] = (val >> 24) & 0xFF

def write_reg(registradores, reg_name, val):
    """Escreve em um registrador descartando escritas no x0."""
    if reg_name != "x0":
        registradores[reg_name] = to_int32(val)


# PASSO 1: PARSER E CONSTRUÇÃO DAS TABELAS (ROTULOS E INSTRUCOES)

def carregar_programa(filename):
    registradores = {f"x{i}": 0 for i in range(32)}
    memoria = {}
    rotulos = {}
    instrucoes = {}

    text_pc = 0x00000000
    data_addr = 0x00200000
    current_section = ".text"

    with open(filename, "r", encoding="utf-8") as f:
        raw_lines = f.readlines()

    for raw_line in raw_lines:
        line = raw_line.split("#")[0].strip()
        if not line:
            continue

        while ":" in line:
            label_part, rest_part = line.split(":", 1)
            label = label_part.strip()
            if label:
                if current_section == ".text":
                    rotulos[label] = text_pc
                else:
                    rotulos[label] = data_addr
            line = rest_part.strip()

        if not line:
            continue

        parts = line.split(maxsplit=1)
        item = parts[0]
        args_str = parts[1] if len(parts) > 1 else ""

        mnemonic_dir = item.lstrip(".").lower()

        if mnemonic_dir == "text":
            current_section = ".text"
            continue
        elif mnemonic_dir == "data":
            current_section = ".data"
            continue
        elif mnemonic_dir == "globl":
            continue

        if current_section == ".data":
            args = [a.strip() for a in args_str.split(",") if a.strip()]
            if mnemonic_dir == "word":
                for a in args:
                    write_word(memoria, data_addr, parse_int(a))
                    data_addr += 4
            elif mnemonic_dir == "half":
                for a in args:
                    write_half(memoria, data_addr, parse_int(a))
                    data_addr += 2
            elif mnemonic_dir == "byte":
                for a in args:
                    write_byte(memoria, data_addr, parse_int(a))
                    data_addr += 1
            elif mnemonic_dir in ("zero", "space"):
                if args:
                    n = parse_int(args[0])
                    for i in range(n):
                        write_byte(memoria, data_addr + i, 0)
                    data_addr += n
            elif mnemonic_dir == "align":
                if args:
                    n = parse_int(args[0])
                    align_bytes = 1 << n
                    rem = data_addr % align_bytes
                    if rem != 0:
                        data_addr += align_bytes - rem
            continue

        if current_section == ".text":
            args = [a.strip() for a in args_str.split(",") if a.strip()]
            campos = [item.lower()] + args
            instrucoes[text_pc] = campos
            text_pc += 4

    return registradores, memoria, rotulos, instrucoes


# EXECUÇÃO DE UMA INSTRUÇÃO

def executar(campos, registradores, memoria, rotulos, pc):
    """
    Executa a instrução dada por 'campos'.
    Retorna uma tupla (novo_pc, alterou_pc, sinal_termino).
    """
    op = campos[0]

    # 1. Pseudoinstruções
    if op == "li":
        rd = parse_reg(campos[1])
        imm = parse_int(campos[2])
        write_reg(registradores, rd, imm)
        return pc, False, False

    elif op == "la":
        rd = parse_reg(campos[1])
        lbl = campos[2].strip()
        write_reg(registradores, rd, rotulos[lbl])
        return pc, False, False

    elif op == "mv":
        rd = parse_reg(campos[1])
        rs = parse_reg(campos[2])
        write_reg(registradores, rd, registradores[rs])
        return pc, False, False

    elif op == "j":
        lbl = campos[1].strip()
        return rotulos[lbl], True, False

    elif op == "jr":
        rs = parse_reg(campos[1])
        return registradores[rs], True, False

    # 2. R-Type
    elif op in ("add", "sub", "sll", "slt", "sltu", "xor", "srl", "sra", "or", "and", "mul", "div", "rem"):
        rd = parse_reg(campos[1])
        rs1 = parse_reg(campos[2])
        rs2 = parse_reg(campos[3])
        v1 = registradores[rs1]
        v2 = registradores[rs2]

        if op == "add":
            res = v1 + v2
        elif op == "sub":
            res = v1 - v2
        elif op == "sll":
            res = v1 << (v2 & 0x1F)
        elif op == "slt":
            res = 1 if v1 < v2 else 0
        elif op == "sltu":
            res = 1 if to_uint32(v1) < to_uint32(v2) else 0
        elif op == "xor":
            res = v1 ^ v2
        elif op == "srl":
            res = to_uint32(v1) >> (v2 & 0x1F)
        elif op == "sra":
            res = v1 >> (v2 & 0x1F)
        elif op == "or":
            res = v1 | v2
        elif op == "and":
            res = v1 & v2
        elif op == "mul":
            res = v1 * v2
        elif op == "div":
            if v2 == 0:
                res = -1
            elif v1 == -2147483648 and v2 == -1:
                res = -2147483648
            else:
                res = int(v1 / v2)
        elif op == "rem":
            if v2 == 0:
                res = v1
            elif v1 == -2147483648 and v2 == -1:
                res = 0
            else:
                res = v1 - int(v1 / v2) * v2

        write_reg(registradores, rd, res)
        return pc, False, False

    # 3. I-Type aritmética
    elif op in ("addi", "slti", "sltiu", "ori", "andi", "slli", "srli", "srai"):
        rd = parse_reg(campos[1])
        rs1 = parse_reg(campos[2])
        imm = parse_int(campos[3])
        v1 = registradores[rs1]

        if op == "addi":
            res = v1 + imm
        elif op == "slti":
            res = 1 if v1 < imm else 0
        elif op == "sltiu":
            res = 1 if to_uint32(v1) < to_uint32(imm) else 0
        elif op == "ori":
            res = v1 | imm
        elif op == "andi":
            res = v1 & imm
        elif op == "slli":
            res = v1 << (imm & 0x1F)
        elif op == "srli":
            res = to_uint32(v1) >> (imm & 0x1F)
        elif op == "srai":
            res = v1 >> (imm & 0x1F)

        write_reg(registradores, rd, res)
        return pc, False, False

    # 4. I-Type load
    elif op in ("lb", "lh", "lw", "lbu", "lhu"):
        rd = parse_reg(campos[1])
        offset, rs1 = parse_mem_operand(campos[2])
        addr = registradores[rs1] + offset

        if op == "lb":
            res = read_byte_s(memoria, addr)
        elif op == "lh":
            res = read_half_s(memoria, addr)
        elif op == "lw":
            res = read_word_s(memoria, addr)
        elif op == "lbu":
            res = read_byte_u(memoria, addr)
        elif op == "lhu":
            res = read_half_u(memoria, addr)

        write_reg(registradores, rd, res)
        return pc, False, False

    # 5. S-Type store
    elif op in ("sb", "sh", "sw"):
        rs2 = parse_reg(campos[1])
        offset, rs1 = parse_mem_operand(campos[2])
        addr = registradores[rs1] + offset
        val = registradores[rs2]

        if op == "sb":
            write_byte(memoria, addr, val)
        elif op == "sh":
            write_half(memoria, addr, val)
        elif op == "sw":
            write_word(memoria, addr, val)

        return pc, False, False

    # 6. B-Type branch
    elif op in ("beq", "bne", "blt", "bge", "bltu", "bgeu"):
        rs1 = parse_reg(campos[1])
        rs2 = parse_reg(campos[2])
        lbl = campos[3].strip()
        v1 = registradores[rs1]
        v2 = registradores[rs2]

        cond = False
        if op == "beq":
            cond = v1 == v2
        elif op == "bne":
            cond = v1 != v2
        elif op == "blt":
            cond = v1 < v2
        elif op == "bge":
            cond = v1 >= v2
        elif op == "bltu":
            cond = to_uint32(v1) < to_uint32(v2)
        elif op == "bgeu":
            cond = to_uint32(v1) >= to_uint32(v2)

        if cond:
            return rotulos[lbl], True, False
        return pc, False, False

    # 7. Sistema
    elif op == "ecall":
        a7 = registradores["x17"]
        if a7 == 10:
            return pc, False, True
        elif a7 == 1:
            val = registradores["x10"]
            print(val, end="")
            return pc, False, False
        return pc, False, False

    else:
        raise ValueError(f"Instrução não reconhecida: '{op}'")


def main():
    if len(sys.argv) < 2:
        print("Uso correto: python emulador.py codigo.s")
        sys.exit(1)

    filename = sys.argv[1]
    registradores, memoria, rotulos, instrucoes = carregar_programa(filename)

    if "main" not in rotulos:
        raise ValueError("Rótulo 'main' não encontrado no código-fonte.")

    pc = rotulos["main"]

    while True:
        if pc not in instrucoes:
            break

        campos = instrucoes[pc]
        novo_pc, pc_alterado, exit_signal = executar(
            campos, registradores, memoria, rotulos, pc
        )

        if exit_signal:
            break

        if pc_alterado:
            pc = novo_pc
        else:
            pc += 4


main()