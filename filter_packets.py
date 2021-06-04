import re

def filter(filename):
    regex = r"(?s)\b(?:(?!\n\n).)*?\b(ping)\b(?:(?!\n\nNo\.).)*"

    data = open(filename).read()
    
    matches = re.finditer(regex, data, re.MULTILINE)
    
    filename_split = filename.split('.')
    filename_join = '_filtered.'.join(filename_split)

    out_file = open(filename_join,'w')
    
    for match in matches:
        line = str(match.group(0))+'\n\n'
        out_file.write(line)

    out_file.close()
