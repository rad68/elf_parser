#
#   Method to parse elf header
#
def ParseElfHeader(self, elf_file):

  word   = ''
  header_offset = 0

  elf_offset_32 = { 
    3  : 'magic',   4  : 'class',       5  : 'data',      6  : 'version',
    7  : 'osabi',   8  : 'abiversion',  15 : 'pad',       17 : 'type',
    19 : 'machine', 23 : 'e_version',   27 : 'e_entry',   31 : 'e_phoff',
    35 : 'e_shoff', 39 : 'e_flags',     41 : 'e_ehsize',  43 : 'e_phentsize',
    45 : 'e_phnum', 47 : 'e_shentsize', 49 : 'e_shnum',   51 : 'e_shstrndx'
  }

  elf_offset_64 = {
    3  : 'magic',   4  : 'class',       5  : 'data',      6  : 'version',
    7  : 'osabi',   8  : 'abiversion',  15 : 'pad',       17 : 'type',
    19 : 'machine', 23 : 'e_version',   31 : 'e_entry',   39 : 'e_phoff',
    47 : 'e_shoff', 51 : 'e_flags',     53 : 'e_ehsize',  55 : 'e_phentsize',
    57 : 'e_phnum', 59 : 'e_shentsize', 61 : 'e_shnum',   63 : 'e_shstrndx'
  }

  elf_header = {}

  #reading magic elf header
  for i in range(0,16):
    if (elf_offset_32.get(header_offset) != None):
      word = word + str(elf_file.read(1).hex())
      elf_header[elf_offset_32[header_offset]] = word
      word = ''
    else:
      word = word + str(elf_file.read(1).hex())
    header_offset = header_offset + 1

  bitness = int(elf_header['class'],16)
  endianness = int(elf_header['data'],16)

  #define system parameters
  if (bitness == 1):
    elf_offset = elf_offset_32
    elf_header_size = 52 - 16
  elif (bitness == 2):
    elf_offset = elf_offset_64
    elf_header_size = 64 - 16

  #reading the rest of the header
  for i in range(0,elf_header_size):
    if (elf_offset.get(header_offset) != None):
      if (endianness == 1):
        word = str(elf_file.read(1).hex()) + word
      elif (endianness == 2):
        word = word + str(elf_file.read(1).hex())
      elf_header[elf_offset[header_offset]] = word
      word = ''
    else:
      if(endianness == 1):
        word = str(elf_file.read(1).hex()) + word
      elif(endianness == 2):
        word = word + str(elf_file.read(1).hex())
    header_offset = header_offset + 1

  return elf_header

#
#   Function to parse program headers
#
def ParseProgramHeader (self, elf_file):

  elf_file.seek(0)
  elf_file.read(int(self.elf_header['e_phoff'],16))

  word = ''
  header_offset = 0

  program_offset_32 = {
    3  : 'p_type',  7  : 'p_offset',  11 : 'p_vaddr', 15 : 'p_paddr',
    19 : 'p_filesz',  23 : 'p_memsz', 27 : 'p_flags', 31 : 'p_align'
  }
  
  program_offset_64 = {
    3  : 'p_type',  7  : 'p_flags', 15 : 'p_offset',  23 : 'p_vaddr',
    31 : 'p_paddr', 39 : 'p_filesz',  47 : 'p_memsz', 55 : 'p_align'
  }

  program_header_list = []
  program_header = {}
  program_header_size = int(self.elf_header['e_phentsize'],16)
  program_header_number = int(self.elf_header['e_phnum'],16)
  
  bitness = int(self.elf_header['class'],16)
  endianness = int(self.elf_header['data'],16)

  if (bitness == 1):
    program_offset = program_offset_32
  elif (bitness == 2):
    program_offset = program_offset_64

  for j in range(0, program_header_number):
    for i in range(0, program_header_size):
      if (program_offset.get(header_offset) != None):
        if (endianness == 1):
          word = str(elf_file.read(1).hex()) + word
        elif (endianness == 2):
          word = word + str(elf_file.read(1).hex())
        program_header[program_offset[header_offset]] = word
        word = ''
      elif (endianness == 1):
        word = str(elf_file.read(1).hex()) + word
      elif (endianness):
        word = word + str(elf_file.read(1).hex())
      header_offset += 1
    program_header_list.append(program_header)
  
    program_header = {}
    header_offset = 0

  return program_header_list

#
#   Function to parse section headers
#
def ParseSectionHeader (self, elf_file):

  elf_file.seek(0)
  elf_file.read(int(self.elf_header['e_shoff'],16))

  word = ''
  header_offset = 0

  section_offset_32 = {
    3 : 'sh_name',        7 : 'sh_type',  11 : 'sh_flags',  15 : 'sh_addr',
    19 : 'sh_offset',     23 : 'sh_size', 27 : 'sh_link',   31 : 'sh_info',
    35 : 'sh_addralign',  39 : 'sh_entsize'
  }
  
  section_offset_64 = {
    3 : 'sh_name',        7 : 'sh_type',  15 : 'sh_flags',  23 : 'sh_addr',
    31 : 'sh_offset',     39 : 'sh_size', 43 : 'sh_link',   47 : 'sh_info',
    55 : 'sh_addralign',  63 : 'sh_entsize'
  }

  section_header_list = []
  section_header = {}
  section_header_size = int(self.elf_header['e_shentsize'],16)
  section_header_number = int(self.elf_header['e_shnum'], 16)
  
  bitness = int(self.elf_header['class'],16)
  endianness = int(self.elf_header['data'],16)

  if (bitness == 1):
    section_offset = section_offset_32
  elif (bitness == 2):
    section_offset = section_offset_64

  for j in range(0, section_header_number):
    for i in range(0,section_header_size):
      if (section_offset.get(header_offset) != None):
        if (endianness == 1):
          word = str(elf_file.read(1).hex()) + word
        elif (endianness == 2):
          word = word + str(elf_file.read(1).hex())
        section_header[section_offset[header_offset]] = word
        word = ''
      else:
        if (endianness == 1):
          word = str(elf_file.read(1).hex()) + word
        elif (endianness == 2):
          word = word + str(elf_file.read(1).hex())
      header_offset += 1
    section_header_list.append(section_header)
  
    section_header = {}
    header_offset = 0

  return section_header_list

#
#   Function to parse code section
#
def ParseSection (self, elf_file):

  word = ''
  word_len = 0

  global_offset = 0
  section = {}  #addr -> word
  section_map = {} # section name -> section
  
  for sec in self.section_header_list:
    elf_file.seek(0)
    elf_file.read(int(sec['sh_offset'],16))
    global_offset = int(sec['sh_addr'],16)
    section_size = int(sec['sh_size'],16)
    word = ''
    for i in range(0, section_size):
      if (word_len == 7):
        word = str(elf_file.read(1).hex()) + word
        section[global_offset] = word
        global_offset += word_len + 1
        word_len = 0
        word = ''
      elif(i == section_size - 1):
        word = str(elf_file.read(1).hex()) + word
        section[global_offset] = word
        global_offset += word_len + 1
        word_len = 0
        word = ''
      else:
        word = str(elf_file.read(1).hex()) + word
        word_len += 1
  
    section_map[sec['sh_name']] = section
    section = {}

  return section_map

#
#   Function to Dump all sections headers
#
def DumpSectionHeaderAll(self):

  for section in self.section_header_list:
    for field in section:
      print(field + " : " + section[field])
    print("")

#
#   Function to Dump all sections
#
def DumpSectionAll(self):

  for section_name in self.section_map:
    for section_addr in self.section_map[section_name]:
      print (section_addr + " : " + self.section_map[section_name][section_addr])

#
#   Function to dump all sections going into image
#
def DumpSectionImageAll(self):

  sf = 0
  for section_name in self.section_map:
    for section in self.section_header_list:
      if (section['sh_name'] == section_name):
        if (int(section['sh_type'],16) == 1):
          sf = 0
        else:
          sf = 1
        break
    if (sf == 1):
      continue
    for section_addr in self.section_map[section_name]:
      print (str(hex(section_addr)) + " : " + self.section_map[section_name][section_addr])
    print("")

#
#   Function to dump mempry image with 64bit length
#
def DumpMemoryImageDouble(self):

  word = ''
  memory_image = {} 
  format_memory_image = {}  

  sf = 0
  for section_name in self.section_map:
    for section in self.section_header_list:
      if (section['sh_name'] == section_name):
        if (int(section['sh_type'],16) == 1):
          sf = 0
        else:
          sf = 1
        break
    if (sf == 1):
      continue
    for section_addr in self.section_map[section_name]:
      addr = section_addr
      if (addr % 8 != 0):
        new_addr = addr - addr % 8
        if (memory_image.get(new_addr) != None):
          if (len(memory_image[new_addr]) < 16):
            memory_image[new_addr] = "00000000" + memory_image[new_addr]
          word = self.section_map[section_name][section_addr]
          if (len(word) < 16):
            word = "00000000" + word
          memory_image[new_addr] = word[8:16] + memory_image[new_addr][8:16]
          new_addr = new_addr+8
          if (memory_image.get(new_addr) != None):
            memory_image[new_addr] = memory_image[new_addr][0:8] + word[0:8] 
          else:
            memory_image[new_addr] = "00000000" + word[0:8]
        else:
          memory_image[new_addr] = word[0:8] + "00000000"
          new_addr = new_addr + 8
          if (memory_image.get(new_addr) != None):
            memory_image[addr] = memory_image[addr][0:8] + word[0:8] 
          else:
            memory_image[addr] = "00000000" + word[8:16]    
      else:
        if (memory_image.get(section_addr) == None):
          memory_image[section_addr] = self.section_map[section_name][section_addr]
        else:
          memory_image[section_addr] = self.section_map[section_name][section_addr]

  for addr in memory_image:
    hex_addr = str(hex(addr))[2:]
    if (len(hex_addr) < 16):
      hex_addr = "0" * (16 - len(hex_addr)) + hex_addr
    hex_data = memory_image[addr]
    if (len(hex_data) < 16):
      hex_data = hex_data + "0" * (16 - len(hex_data))
    format_memory_image[hex_addr] = hex_data

  return format_memory_image

#
#   Function to parse *.elf file
#
def ParseElf (self, elf_file):

  self.elf_header = ParseElfHeader(self, elf_file)
  self.program_header_list = ParseProgramHeader(self, elf_file)
  self.section_header_list = ParseSectionHeader(self, elf_file)
  self.section_map = ParseSection(self, elf_file)
  

class elfFile:

  def __init__ (self, ef):
    self.elf_header = {}
    self.program_header_list = []
    self.section_header_list = []
    self.section_map = {}
    self.__ParseElf(open(ef,'rb'))

  __ParseElf = ParseElf
  __ParseElfHeader = ParseElfHeader
  __ParseProgramHeader = ParseProgramHeader
  __ParseSectionHeader = ParseSectionHeader

  DumpSectionHeaderAll = DumpSectionHeaderAll
  DumpSectionAll = DumpSectionAll
  DumpSectionImageAll = DumpSectionImageAll
  DumpMemoryImageDouble = DumpMemoryImageDouble

