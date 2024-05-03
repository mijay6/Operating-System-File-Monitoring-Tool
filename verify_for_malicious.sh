#!/bin/bash

#verificam nr de argumente dat ca parametru
if test $# -ne 1
then
    echo "Eroare: numar de argumente la verificarea fisier maliios invalid.\n"
    exit 1
fi

# asignam argumentul dat cu o variabila
fis="$1"

#dam drepturi de citire la fisier.
chmod +r "$1"

#variabile de rezultat
suspect=0
periculos=0

#definim nr max de lini, cuvinte si caractere

max_linii=100
max_cuvinte=5000
max_caractere=10000

#definim cuvinte cheie malitioase

string1="corrupted"
string2="dangerous"
string3="risk"
string4="attack"
string5="malware"
string6="malicious"

# aflam numarul de lini, cuvinte si caractere din fisier

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

# verificam numarul de lini, cuvinte si caractere din fisier

if ["$linii" -ge "$max_linii" -o "$cuvinte" -ge "max_cuvinte" -o "$caractere" -ge "max_caractere"]
then
    periculos=1
    chmod -r "$fis"
    echo "$fis"
    exit $periculos
fi


# daca fisierul are mai putin de 3 linii si mai mult de 1000 de cuvinte sau 2000 de caractere,
# atunci fisierul este considerat suspect

if [ "$linii" -lt 3 -a "$cuvinte" -gt 1000 -a "$caractere" -gt 2000 ]
then
    suspect=1
fi

# daca fisierul e considerat suspect si daca gasim cuvintele cheie in fisierul dat ca parametru,
# atunci fisierul este considerat periculos


if [ "$suspect" -eq 1 ]
then

    # grep va cauta una din aceste cuvinte si cand va gasi una, va termina de cautat

    grep -m 1 -e "$string1" -e "$string2" -e "$string3" -e "$string4" -e "$string5" -e "$string6" "$fis"
    
    # daca o gasit setam variabila periculos pe 1
    
    if [ $? -eq 0 ]; then
        periculos=1;
        chmod -r "$fis"
        echo "$fis"
        exit $periculos
    fi
fi

# daca fisierul este suspect, atunci verificam daca exista caractere non-ASCII in fisier

if [ "$suspect" -eq 1 ]
then

    # daca o gasit setam variabila periculos pe 1

    if grep -q "[0x80-0xFF]" "$fis"
    then
        periculos=1
        chmod -r "$fis"
        echo "$fis"
        exit $result
    fi
fi

if [ "$suspect" -eq 0 ]
then
    echo "SAFE"
fi

# scoatem drepturile de citire a fisierului
chmod -r "$fis"   # NU INTELEG dece nu merge

#iesim cu un cod de iesire specificat de result
exit $result