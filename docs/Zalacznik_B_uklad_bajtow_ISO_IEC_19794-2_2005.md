**ZAŁĄCZNIK B  
UKŁAD BAJTÓW REKORDU ISO/IEC 19794-2:2005**

Załącznik przedstawia układ rekordu minutii ISO/IEC 19794-2:2005 w
zakresie zaimplementowanym w prototypie fpscanner. Opis dotyczy
binarnego formatu wymiany danych o minutiach, a nie wewnętrznego formatu
szablonu projektu (.tpl). Wartości wielobajtowe są zapisywane w
kolejności big-endian (najbardziej znaczący bajt jako pierwszy).

# B.1. Struktura rekordu

Rekord składa się z 24-bajtowego nagłówka rekordu, jednego lub większej
liczby nagłówków widoku palca, list minutii przypisanych do widoków oraz
dwubajtowego pola długości danych rozszerzonych. W implementacji
opisanej w pracy pole długości danych rozszerzonych ma zawsze wartość
zero, a bloki rozszerzone nie są obsługiwane.

| **Element**                  | **Rozmiar** | **Opis**                                                                                                                                          |
|------------------------------|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| Nagłówek rekordu             | 24 B        | Identyfikator formatu, wersja, długość rekordu, identyfikacja urządzenia, wymiary i rozdzielczość obrazu, liczba widoków oraz bajt zarezerwowany. |
| Nagłówek widoku palca        | 4 B         | Pozycja palca, numer widoku i typ odbitki, jakość widoku oraz liczba minutii.                                                                     |
| Dane minutii                 | 6 B × N     | Kolejne rekordy minutii; każda minutia zawiera typ, współrzędne X i Y, kąt oraz jakość.                                                           |
| Długość danych rozszerzonych | 2 B         | W prototypie wartość 0; dane rozszerzone nie są implementowane.                                                                                   |

Dla jednego widoku i N minutii długość rekordu wynosi 24 + 4 + 6·N + 2,
czyli 30 + 6·N bajtów. Pole długości całego rekordu w nagłówku musi
odpowiadać rzeczywistej liczbie bajtów.

# B.2. Nagłówek rekordu (24 bajty)

| **Offset** | **Rozmiar** | **Pole**                                                  | **Kodowanie / znaczenie**                                                                                                  |
|------------|-------------|-----------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|
| 0–3        | 4 B         | Format Identifier                                         | Stała ASCII „FMR\0” (hex: 46 4D 52 00).                                                                                    |
| 4–7        | 4 B         | Version Number                                            | Stała ASCII „ 20\0” (hex: 20 32 30 00).                                                                                    |
| 8–11       | 4 B         | Length of Record                                          | Całkowita długość rekordu w bajtach, unsigned integer, big-endian.                                                         |
| 12–13      | 2 B         | Capture Equipment Certifications / Capture Device Type ID | Pole bitowe: 4 najbardziej znaczące bity – certyfikacja urządzenia; 12 najmłodszych bitów – identyfikator typu urządzenia. |
| 14–15      | 2 B         | Image Width                                               | Szerokość obrazu w pikselach, unsigned 16-bit, big-endian.                                                                 |
| 16–17      | 2 B         | Image Height                                              | Wysokość obrazu w pikselach, unsigned 16-bit, big-endian.                                                                  |
| 18–19      | 2 B         | X Resolution                                              | Rozdzielczość pozioma w pikselach na centymetr, unsigned 16-bit, big-endian.                                               |
| 20–21      | 2 B         | Y Resolution                                              | Rozdzielczość pionowa w pikselach na centymetr, unsigned 16-bit, big-endian.                                               |
| 22         | 1 B         | Number of Finger Views                                    | Liczba widoków palców zawartych w rekordzie.                                                                               |
| 23         | 1 B         | Reserved Byte                                             | Bajt zarezerwowany; musi mieć wartość 0.                                                                                   |

Identyfikator i wersja są stałymi znacznikami rozpoznawczymi formatu.
Wartości liczbowe zajmujące więcej niż jeden bajt należy odczytywać w
kolejności big-endian. W prototypie parser sprawdza m.in. znaczniki,
zgodność zadeklarowanej długości z długością danych i zerową wartość
bajtu zarezerwowanego.

# B.3. Nagłówek widoku palca (4 bajty)

| **Offset względny** | **Rozmiar** | **Pole**                      | **Kodowanie / znaczenie**                                            |
|---------------------|-------------|-------------------------------|----------------------------------------------------------------------|
| 0                   | 1 B         | Finger Position               | Pozycja palca w zakresie 0–10.                                       |
| 1                   | 1 B         | View Number / Impression Type | Dwa pola czterobitowe: numer widoku (4 bity) i typ odbitki (4 bity). |
| 2                   | 1 B         | View Quality                  | Jakość widoku w zakresie 0–100.                                      |
| 3                   | 1 B         | Number of Minutiae            | Liczba minutii w bieżącym widoku.                                    |

Numer widoku i typ odbitki są zapisane w jednym bajcie, po cztery bity
każde. W prototypie kontrolowana jest poprawność pozycji palca i jakości
widoku. Powtórzenie tej samej pary (pozycja palca, numer widoku) jest
odrzucane.

# B.4. Struktura pojedynczej minutii (6 bajtów)

Każda minutia jest kodowana w sześciu bajtach. Pierwsze dwa bajty
zawierają typ minutii i współrzędną X, kolejne dwa – bity zarezerwowane
oraz współrzędną Y, a ostatnie dwa bajty – kąt i jakość.

| **Offset względny** | **Rozmiar** | **Pole**        | **Znaczenie**                                                                                        |
|---------------------|-------------|-----------------|------------------------------------------------------------------------------------------------------|
| 0–1                 | 2 B         | Type + X        | Dwa najbardziej znaczące bity określają typ minutii, a pozostałe 14 bitów – współrzędną X.           |
| 2–3                 | 2 B         | Reserved + Y    | Dwa najbardziej znaczące bity są zarezerwowane i mają wartość 0; pozostałe 14 bitów – współrzędną Y. |
| 4                   | 1 B         | Angle           | Kąt w jednostkach 360/256 stopnia.                                                                   |
| 5                   | 1 B         | Minutia Quality | Jakość minutii; 0 oznacza „nie podano”.                                                              |

# B.5. Rozpakowanie pól bitowych

Dla dwóch pierwszych par bajtów należy najpierw złożyć wartości
16-bitowe w porządku big-endian. Następnie z otrzymanych słów wyodrębnia
się odpowiednie bity:

```text
word_x = (byte_0 << 8) | byte_1
type   = (word_x >> 14) & 0b11
x      = word_x & 0x3FFF

word_y = (byte_2 << 8) | byte_3
reserved = (word_y >> 14) & 0b11
y      = word_y & 0x3FFF
```

Wartość pola reserved musi wynosić zero. Kod typu 3 jest w implementacji
niedozwolony. Współrzędne X i Y są wyrażone w pikselach obrazu, z
początkiem układu w lewym górnym rogu: X rośnie w prawo, a Y w dół.

# B.6. Kodowanie kąta i konwencja kierunku

Kąt zapisuje się w jednym bajcie jako liczbę całkowitą od 0 do 255.
Jedna jednostka odpowiada 360/256 stopnia, zatem wartość kąta w
stopniach oblicza się ze wzoru:

**θ\[°\] = angle × 360 / 256**

Kąt 0 oznacza kierunek w prawo, a wartość rośnie przeciwnie do ruchu
wskazówek zegara, zgodnie z konwencją opisaną w pracy. Przy konwersji z
formatu wewnętrznego projektu kąt w radianach jest kwantyzowany do
najbliższej wartości jednostki formatu. Dla minutii typu rozwidlenie
(bifurcation) implementacja obraca kierunek o 180° ze względu na różnicę
konwencji kierunku pomiędzy formatem projektu a ISO. Dla zakończenia
(ridge ending) obrót nie jest wykonywany.

# B.7. Dane rozszerzone i ograniczenia implementacji

Po zapisaniu wszystkich widoków rekord zawiera dwubajtowe pole długości
danych rozszerzonych. W prototypie pole to ma wartość 0, co oznacza brak
bloków rozszerzonych. Parser odrzuca rekordy zawierające bloki
rozszerzone, bajty nadmiarowe, niezerowe bity zarezerwowane,
nieprawidłowe wartości pól oraz niezgodność długości rekordu.

Implementacja ogranicza liczbę minutii w pojedynczym widoku do
maksymalnej wartości możliwej do zapisania w jednobajtowym polu liczby
minutii (255). Większa liczba minutii jest błędem – dane nie są
automatycznie przycinane. Jakość minutii jest eksportowana jako 0 („nie
podano”), natomiast jakość widoku przyjmuje domyślnie wartość 100.
Minutie typu „inny” przy imporcie są mapowane na zakończenia albo
pomijane / odrzucane zależnie od parametru narzędzia.

Opisany układ jest zakresem obsługiwanym przez prototyp, a nie
deklaracją pełnej zgodności ze wszystkimi opcjonalnymi elementami normy.
W pracy wskazano, że układ nagłówka i pól minutii oparto na publicznej
dokumentacji formatu i ręcznie przygotowanym rekordzie wzorcowym; nie
przeprowadzono weryfikacji certyfikowanym narzędziem zgodności. Przed
wykorzystaniem rekordów w wymianie z systemami zewnętrznymi zalecana
jest niezależna walidacja.

# B.8. Różnica między rekordem ISO a szablonem wewnętrznym .tpl

Format ISO/IEC 19794-2:2005 jest formatem wymiany danych na granicy
systemu. Wewnętrzny szablon projektu .tpl ma odmienną strukturę: bajt
wersji (1 B), liczba minutii (2 B), a następnie wpisy minutii po 7
bajtów (X – 2 B, Y – 2 B, kąt – 2 B, typ – 1 B). Jakość minutii nie jest
w nim zapisywana. Serwer prototypu przechowuje i przesyła szablony w
formacie .tpl; konwersja do i z ISO jest realizowana przez moduł
biometrics/iso19794.py oraz narzędzie fp-iso.

# B.9. Podsumowanie układu

| **Sekcja**                   | **Długość**   | **Uwagi**                                         |
|------------------------------|---------------|---------------------------------------------------|
| Nagłówek rekordu             | 24 B          | Stały rozmiar.                                    |
| Nagłówek widoku              | 4 B na widok  | Liczba widoków określona w nagłówku rekordu.      |
| Minutie                      | 6 B na minutę | Liczba minutii wskazana w nagłówku danego widoku. |
| Długość danych rozszerzonych | 2 B           | W prototypie 0.                                   |

Dla pojedynczego widoku zawierającego N minutii całkowita długość wynosi
30 + 6·N bajtów. Dla rekordu wielowidokowego długość należy obliczyć
jako 24 + suma(4 + 6·Nᵢ dla każdego widoku i) + 2.

# Źródła

1\. ISO/IEC 19794-2:2005, Information technology — Biometric data
interchange formats — Part 2: Finger minutiae data.
