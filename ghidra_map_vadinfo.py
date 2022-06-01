# Maps a Volatility 3 vadinfo output to memory with appropriate virtual addresses.  
# Example vadinfo output
# py E:\tools\volatility3\vol.py -f .\memory_dump -o 644_vadinfo windows.vadinfo --pid 644 --dump > vadinfo.out
# Set the VADInfo stdout to vadinfo.out
# and the VADInfo directory to 644_vadinfo

#@author Kroll Cyber 

#@category Memory


import csv
import os
from ghidra.program.model.mem import MemoryConflictException

# Obtain output directory
vad_file = askFile("Volatility VADInfo stdout", "Select").toString()
vad_dir = askDirectory("Volatility VADInfo directory", "Select").toString()

vad_sections = list()
with open(vad_file) as fin:
    fin.readline()
    fin.readline()
    reader = csv.DictReader(fin, delimiter='\t')
    for line in reader:
        vad_sections.append(line)

# Retrieve program memory: 
# https://ghidra.re/ghidra_docs/api/ghidra/program/database/ProgramDB.html#getMemory()
mem_obj = currentProgram.getMemory()

for vad in vad_sections:
    # parseAddress: 
    # https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html#parseAddress(java.lang.String)
    vpn_start = parseAddress(vad['Start VPN'])
    if vad['File output'] == 'Error outputting file':
        continue
    fname = vad['File output']
    fpath = os.path.join(vad_dir, fname)

    # Create FileBytes object after getting file size
    size = os.path.getsize(fpath)
    with open(fpath, 'rb') as fin:
        # https://ghidra.re/ghidra_docs/api/ghidra/program/database/mem/MemoryMapDB.html#createFileBytes(java.lang.String,long,long,java.io.InputStream,ghidra.util.task.TaskMonitor)
        file_bytes = mem_obj.createFileBytes(
            fname,
            0,
            size,
            fin,
            monitor # Monitor is defined by Ghidra
        )
    # Using the filebytes object to create memory
    # https://ghidra.re/ghidra_docs/api/ghidra/program/database/mem/MemoryMapDB.html#createInitializedBlock(java.lang.String,ghidra.program.model.address.Address,ghidra.program.database.mem.FileBytes,long,long,boolean)
    try:
        block = mem_obj.createInitializedBlock(
            fname,
            vpn_start,
            file_bytes,
            0,
            size,
            False
        )
    except MemoryConflictException:
        continue

    # Set a few values
    # https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/MemoryBlock.html
    if vad['File'] != 'N/A':
        block.setSourceName(vad['File'])
    block.setRead('READ' in vad['Protection'])
    block.setWrite('WRITE' in vad['Protection'])
    block.setExecute('EXECUTE' in vad['Protection'])
    
