Albu Robert Marian 322CC

Pentru aceasta tema am avut de implementat dataplane-ul unui router cu
ajutorulul unui simulator.

In momentul in care primim un pachet, determinam adresa IP finala la care trebuie
sa ajunga si consultam o tabela de rutare pusa la dispozitie, avem doua. Ideea este sa 
gasim prefixul cu masca cea mai stricta ce se potriveste cu Ip-ul destinatie, caruia ii aplicam 
si lui aceeasi masca. Aceasta intrare din tabela de rutare ne va oferi urmatoarea adresa IP
la care vom trimite pachetul, cat si interfata utilizata pentru acest eveniment. Dupa aflarea
interfetei, vom afla adresa MAC a acesteia, folosindu-ne de alta tabela, si vom afla si adresa
MAC pentru urmatorul router la care trimitem pachetul cu ajutorul adresei IP aflate din tabela 
de rutare. 

Trebuie sa luam in considerare cateva aspecte, la fiecare pas verificam daca datele din pachet
s-au corupt pe drum, folosindu-ne de o functie checksum, trebuie sa tinem cont de TTL(Time to Live),
il decrementam pe masura ce parcurgem routerele, iar in momentul in care ajunge 1 aruncam pachetul, si 
mai trebuie sa si verificam daca tipul pachetului este de tip "Echo request". In cazul in care este,
ne vom folosi de protocolul ICMP, pe care il voi descrie mai jos.

Bun, acest protocol este folosit pentru a face anunturi, in momentul in care un pachet expira, trebuie
sa anuntam cumva sursa ca asta s-a intamplat. Pachetele au un timp de viata ca sa nu se petreaca loop-uri
intre routere. Routerul care detecteaza ca un pachet a expirat va trimitite un pachet cu protocol ICMP 
inapoi la sursa. Stie unde sa ajunga pentru ca preia adresa IP a sursei din headerul IP al pachetului aruncat. 
Trebuie sa anuntam si in situatia in care nu se gaseste destinatia in tabela de rutare, sau daca se petrece
situatia de mai sus, "Echo request". In acel moment trebuie returnat un pachet ICMP "Echo reply" tot la routerul
care a trimis pachetul "Echo request".

Routerele implementate vor ignora pachetele care nu folosesc protocolul IPv4, adresele IP fiind pe 32 de biti.
Am avut 4 task-uri de implementat, am reusit sa rezolv numai 3. Ma folosesc de o tabela ARP statica in loc sa o 
creez dinamic. Procesul de dirijare l-am explicat mai sus, pachetul va avea mereu un header ethernet care va mentine
adresa MAC a sursei si a destinatiei, precum si un header IP care contine adresa IP a sursei si a destiantiei, acestea 
nu se schimba in timp ce pachetul se deplaseaza, dar headerul ethernet o face. 

Pentru Longest Prefix Match am ales sa ordonez tabela de rutare in functie de valoarea returnata de catre masti asupra
prefixelor si sa fac o cautare binara pentru gasirea urmatoarei adrese IP. Gasesc o valoare corecta pentru prefix, iar 
apoi caut inainte si inapoi prefixul respectiv cu masca cea mai lunga. 

Protocolul ICMP este cel care anunta sursa de la care a provenit pachetul, am creat functia icmp care genereaza de la 0
un nou buffer pentru noul pachet ICMP si preia informatiile necesare din vechiul pachet, in functie de situatie: daca e
de tip "Echo request" vrem sa copiem toate datele de dupa IP Header, iar daca nu, doar primii 8 bytes pentru a se prinde 
sursa care a fost treaba cu acel pachet.

Disclaimer:

M-am inspirat din laboratorul 4 pentru functia get_mac_entry, dar oricum este un for simplu care doar parcurge tabela ARP,
si am luat cateva linii ce se afla in main, pentru ca mi s-au parut foarte utile pentru tema, cu modificarile necesare acolo
unde era nevoie.

M-am folosit, ca sa inteleg mai bine tema, de videoclipurile puse la dispozitie si in mare parte de wikipedia, iar cand ceva
nu imi era clar m-am folosit si de ChatGPT pentru lamuriri, pentru a intelege mai bine ideea din spate si conceptul.



