import ida_allins
import ida_ua
import idc

def is_instruction(insn, itype, otypes = None):
    if insn.itype != itype:
        return False
    if not otypes:
        return True
    for i, otype in enumerate(otypes):
        if insn.ops[i].type == idc.o_void:
            break;
        if otype and (insn.ops[i].type != otype):
            return False
    return True

def int_to_bytes_little_endian(i, bitcount):
    return [(i >> shift) & 0xFF for shift in range(0, bitcount, 8)]

def decrypt_xorstr(data):
    if not data:
        return
        
    if len(data) % 2:
        data = data[1:]
    
    div = int(len(data)/2)   
    lhs = data[:div]
    rhs = data[div:]
    
    xored = []
    for l, r in zip(lhs, rhs):
        xored.extend(int_to_bytes_little_endian((l ^ r), 64))
        
    result = ""
    for x in xored:
        if not x:
            break
        result += chr(x)
    print(result)

def are_operands_64_bit(insn):
    for op in insn.ops:
        if op.type == idc.o_void:
            break
        if ida_ua.get_dtype_size(op.dtype) != 8:
            return False
    return True

def decrypt_function_xor_strings(funcea):
    xor_data_by_reg = [None] * 16
    xor_data = []
    
    for (cstart, cend) in Chunks(funcea):
        ea = cstart
        while ea < cend:
            insn = idautils.DecodeInstruction(ea)
            ea = idc.next_head(ea)
            
            if is_instruction(insn, ida_allins.NN_xorps):
                decrypt_xorstr(xor_data)
                xor_data = []
                continue
            
            if is_instruction(insn, ida_allins.NN_mov, [idc.o_displ, idc.o_reg]) and are_operands_64_bit(insn):
                if xor_data_by_reg[insn.ops[1].reg]:
                    xor_data.append(xor_data_by_reg[insn.ops[1].reg])
                continue
            
            if is_instruction(insn, ida_allins.NN_mov, [idc.o_reg, idc.o_imm]) and are_operands_64_bit(insn):
                xor_data_by_reg[insn.ops[0].reg] = insn.ops[1].value
                continue
