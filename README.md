# Pristupni rad

Pristupni rad iz kolegija *Primijenjena kriptografija* na specijalističkom studiju informacijske sigurnosti na Fakultetu elektrotehnike i računarstva Sveučilišta u Zagrebu.

Ovaj repozitorij sadrži implementaciju programa za šifriranje i dešifriranje datoteka pomoću simetričnih algoritama. Program podržava različite načine unosa lozinke, kao i različite funkcije za derivaciju ključa iz lozinke.

## Prevođenje
Za prevođenje programa potrebno je imati instaliranu OpenSSL biblioteku:
```bash
sudo apt-get install libssl-dev
```

Program se može prevesti pomoću naredbe:
```bash
make
```

## Korištenje
Program se koristi iz komandne linije. Primjer korištenja:
```bash
./prikri e input.txt # Rezultat će biti spremljen u input.txt.enc
./prikri d input.txt.enc # Rezultat će biti spremljen u input.txt.enc.dec
cmp input.txt input.txt.enc.dec # Ova naredba neće ispisati ništa ako su datoteke identične
```
Program podržava različite opcije, koje se mogu vidjeti pomoću naredbe:
```bash
./prikri -h
```

## Testiranje
Testiranje se može izvršiti pomoću naredbe:
```bash
./test-all.sh
```

Skripta će pokrenuti šifriranje i dešifriranje testne datoteke za svaki par simetričnih algoritama i funkcija za derivaciju ključa.
