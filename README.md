# TAKP-Client-Underthehood
Instructions to see TAKP Client source code:

Start by Downloading and/or cloning this repo. Now you are ready to begin.

1. Download Ghidra

2. Move ghidra_memory_address_function_name_import.py into your Ghidra_scripts folder

3. Open one of the following in Ghidra:
<br>   a. eqgame.exe
<br>   b. eqgfx_dx8.dll
<br>   c. eqmain.dll
<br>   d. eqw.dll
<br>   e. eqwgfix.exe

4. Prior to any Auto Analysis, use the Script Manager to run the script ghidra_memory_address_function_name_import.py 

5. Select the associated function list to import of the file you selected in #3

6. Run Auto Analysis in Ghidra

7. Your Ghidra decompile will now show TAKP Client source code in Psuedo C format for the selected file
