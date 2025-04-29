#!/bin/bash

# Check the number of arguments provided as a parameter
if test $# -ne 1
then
    echo "Error: Invalid number of arguments for malicious file verification.\n"
    exit 1
fi

# Assign the provided argument to a variable
fis="$1"

# Grant read permissions to the file
chmod 400 "$1"

# Result variables
suspect=0
periculos=0

# Define the maximum number of lines, words, and characters
max_linii=100
max_cuvinte=5000
max_caractere=10000

# Define malicious keywords
string1="corrupted"
string2="dangerous"
string3="risk"
string4="attack"
string5="malware"
string6="malicious"

# Find the number of lines, words, and characters in the file
i=0
linii=0
cuvinte=0
caractere=0

for entity in $(wc "$fis")
do
    if test "$i" -eq 0
    then 
        linii=$entity
        i=1
    elif test "$i" -eq 1
    then 
        cuvinte=$entity
        i=2
    elif test "$i" -eq 2
    then 
        caractere=$entity
        i=3
    fi
done

# Check the number of lines, words, and characters in the file
if [ "$linii" -ge "$max_linii" -o "$cuvinte" -ge "$max_cuvinte" -o "$caractere" -ge "$max_caractere" ]
then
    periculos=1
    chmod 000 "$fis"
    echo "$fis"
    exit $periculos
fi

# If the file has fewer than 3 lines and more than 1000 words or 2000 characters,
# then the file is considered suspicious
if [ "$linii" -lt 3 -a "$cuvinte" -gt 1000 -a "$caractere" -gt 2000 ]
then
    suspect=1
fi

# If the file is considered suspicious and if we find the keywords in the file provided as a parameter,
# then the file is considered dangerous
if [ "$suspect" -eq 1 ]
then
    # grep will search for one of these keywords and will stop searching when it finds one
    grep -q -m 1 -e "$string1" -e "$string2" -e "$string3" -e "$string4" -e "$string5" -e "$string6" "$fis"

    # If it finds one, set the variable "periculos" to 1
    if [ $? -eq 0 ]; then
        periculos=1;
        chmod 000 "$fis"
        echo "$fis"
        exit $periculos
    fi
fi

# If the file is suspicious, then check if there are non-ASCII characters in the file
if [ "$suspect" -eq 1 ]
then
    # If it finds any, set the variable "periculos" to 1
    if grep --perl-regexp -q "[^\x00-\x7F]" "$fis"
    then
        periculos=1
        chmod 000 "$fis"
        echo "$fis"
        exit $periculos
    fi
fi

# If the file is not found to be dangerous, print SAFE
echo "SAFE"

# Remove read permissions from the file
chmod 000 "$fis"  

# Exit with a specific exit code based on the result
exit $periculos