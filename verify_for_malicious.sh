#!/bin/bash

#verificam nr de argumente dat ca parametru
if test $# -ne 1
then
    echo "Eroare: numar de argumente la verificarea fisier maliios invalid\n"
    exit 1
fi

# asignam argumentul dat cu o variabila
fis="$1"

#dam drepturi de citire la fisier.
chmod +r "$1"

#variabila de iesire
resutl=0

#definim cuvinte cheie malitioase

string1="corrupted"
string2="dangerous"
string3="risk"
string4="attack"
string5="malware"
string6="malicious"

#daca gasim cuvintele cheie in fisierul dat ca parametru, atunci fisierul este considerat malitios


# grep va cauta una din aceste cuvinte si cand va gasi una, va termina de cautat

grep -m 1 -e "$string1" -e "$string2" -e "$string3" -e "$string4" -e "$string5" -e "$string6" "$fis"

# daca o gasit setam variabila result pe 1

if [ $? -eq 0 ]; then
    result=1;
    chmod -r "$fis"
    exit $result
fi

#if grep -q "$string1" "$fis"; then
#    result=1
#fi

#if grep -q "$string2" "$fis"; then
#    result=1
#fi


# verificam daca exista caractere non-ASCII in fisier
if grep -q "[0x80-0xFF]" "$fis"
then
    result=1
    chmod -r "$fis"
    exit $result
fi

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

if test "$linii" -le 1 -o "$linii" -ge 5
then 
    result=1
fi

if test "$cuvinte" -le 1 -o "$cuvinte" -ge 10
then 
    result=1
fi

if test "$caractere" -le 1 -o "$caractere" -ge 20
then 
    result=1
fi


if test "$linii" -lt 3
then 
    result=1
fi

if test "$cuvinte" -gt 1000
then 
    result=1
fi

if test "$caractere" -gt 2000
then
    result=1
fi

# scoatem drepturile de citire a fisierului
chmod -r "$fis"

#iesim cu un cod de iesire specificat de result
exit $result