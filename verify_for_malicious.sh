#verificam nr de argumente dat ca parametru

if test$# -ne 1
then
    echo "Eroare: numar de argumente la verificarea fisier maliios invalid\n"
    exit 1
fi

# asignam argumentul dat cu o variabila
fis="$1"

#dam drepturi de citire la fisier.
chmod +r fis
