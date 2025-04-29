#TODO Imports function names from a file containing two columns of function names and addresses. Function names have spaces and brackets and there contents removed. Addresses are in hex format. For very large files the script may need to be run multiple times.
#@author Finn Hartshorn, original author source of ghidra_function_name_import.py.  Below is modded version of original. This modded version is called ghidra_memory_address_function_name_import.py
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 


import os.path

from ghidra.program.model.symbol import SourceType #.SourceType import USER_DEFINED

def remove_text_inside_brackets(text, brackets="()[]"):
    count = [0] * (len(brackets) // 2) # count open/close brackets
    saved_chars = []
    for character in text:
        for i, b in enumerate(brackets):
            if character == b: # found bracket
                kind, is_close = divmod(i, 2)
                count[kind] += (-1)**is_close # `+1`: open, `-1`: close
                if count[kind] < 0: # unbalanced bracket
                    count[kind] = 0  # keep it
                else:  # found bracket to remove
                    break
        else: # character is not a [balanced] bracket
            if not any(count): # outside brackets
                saved_chars.append(character)
    return ''.join(saved_chars)

def log_line(file_obj, line):
    file_obj.writelines([line, "\n"])

def add_plate_comment(address, comment, log_file):
    existing_comment = getPlateComment(address)
    if existing_comment and existing_comment != comment:
        log_line(log_file, "Comment already exists at address {} with comment {}".format(address, existing_comment))
        print("Comment already exists at address {} with comment {}".format(address, existing_comment))
        return
    elif not existing_comment:
        log_line(log_file, "Adding comment {} to address {}".format(comment, address))
        print("Adding comment {} to address {}".format(comment, address))
        setPlateComment(address, comment)

functionManager = currentProgram.getFunctionManager()

f = askFile("Give me a file to open", "Go baby go!")

file_name = f.getAbsolutePath()
file_name_no_extension, extension = os.path.splitext(file_name)
log_file_name = file_name_no_extension + ".log"

with open(file_name, "r") as ida_export, open(log_file_name, "w") as ida_import_log:
    for line in ida_export:
        # Check if line starts with "0x" to determine the format
        if line.strip().startswith("0x"):
            # Format is "0xaddress function_name"
            parts = line.strip().split(" ", 1)
            if len(parts) != 2:
                print("Error parsing symbol {} (incorrect format)".format(line))
                continue
                
            address_str = parts[0]
            function_signature = parts[1]
            
            # Parse address
            address = toAddr(address_str).add(int("0x00000000", 16))
            
            # Parse function name
            function_name = remove_text_inside_brackets(function_signature, brackets="()").replace(" ", "")
        else:
            # Original format "function_name 0xaddress"
            pieces = line.split(" 0x")
            if len(pieces) != 2:
                print("Error parsing symbol {} ({})".format(line, len(pieces)))
                continue
                
            # Parse address
            address = toAddr("0x" + pieces[1]).add(int("0x00000000", 16))
            
            # Parse function name
            function_name = remove_text_inside_brackets(pieces[0], brackets="()").replace(" ", "")
            function_signature = pieces[0]

        existing_comment = getPlateComment(address)
        print("Existing comment: {}".format(existing_comment))

        func = functionManager.getFunctionAt(address)
        if func is not None:
            old_name = func.getName()
            if old_name == function_name:
                add_plate_comment(address, function_signature, ida_import_log)
                continue
            try:
                if function_name.startswith(".") and not old_name.startswith("FUN"):
                    log_line(ida_import_log, "Not renaming {} to {}".format(old_name, function_name))
                    continue
                func.setName(function_name, SourceType.USER_DEFINED)
                log_line(ida_import_log, "Renamed function {} to {} at address {}".format(old_name, function_name, address))
                add_plate_comment(address, function_signature, ida_import_log)
            except Exception as e:
                print("Failed to rename function from {} to {} because {}".format(old_name, function_name, e))
                log_line(ida_import_log, "Failed to rename function from {} to {}".format(old_name, function_name))
                continue
        else:
            try:
                func = createFunction(address, function_name)
                log_line(ida_import_log, "Created function {} at address {}".format(function_name, address))
                add_plate_comment(address, function_signature, ida_import_log)
            except:
                print("Failed to create function {}".format(function_name))
                log_line(ida_import_log, "Failed to create function {}".format(function_name))
                continue