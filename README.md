# LandMC AntiProxy

Odrzucanie połączeń przez VPN, proxy i serwerownie — na wejściu do sieci, zanim gracz dojdzie
do jakiegokolwiek backendu.

Zbudowany na [`landmc-platform`](https://github.com/landmc-network/landmc-platform).

## Kolejność sprawdzeń to cała architektura

```text
nick z czarnej listy        → z pamięci
ASN / operator / kraj       → z lokalnych plików GeoLite2
limit połączeń z jednego IP → z pamięci
znany dobry operator (PL)   → z lokalnych plików GeoLite2, KONIEC — bez zapytania
cache adresu                → pamięć, potem baza dzielona przez wszystkie proxy
zewnętrzne API              → dopiero tutaj, i tylko za to się płaci
```

Każde sprawdzenie, na które da się odpowiedzieć lokalnie, jest przed tym, na które się nie da.
Domyślna allowlista zawiera polskich operatorów — Orange, Play, T‑Mobile, Plus, Netię, INEA,
UPC, Vectrę, NASK i kilku mniejszych — więc **normalny gracz z Polski w ogóle nie trafia do
zewnętrznego serwisu**. To jest różnica między setką zapytań dziennie a dziesiątkami tysięcy.

## Czego nie robi

**Nie zamyka sieci, gdy dostawca detekcji ma awarię.** Nieudane sprawdzenie przepuszcza gracza
i zapisuje ostrzeżenie. Anti‑VPN, który przy awarii swojego API blokuje wszystkich, wyrządza
więcej szkody niż VPN‑y, przed którymi miał chronić.

**Nie blokuje wątku.** Wszystko wisi na `EventTask`, więc wolne API opóźnia jedno połączenie, a
nie proxy. Nigdzie nie ma `join()` ani `get()`.

**Nie trzyma kluczy w konfiguracji.** Klucze idą do `proxyradar.key` i `maxmind.key` obok
`config.yml`, albo do zmiennych środowiskowych. Klucz w configu trafia do wklejki przy
pierwszej prośbie o pomoc z ustawieniami.

## Tryby

| `mode` | Zachowanie |
|---|---|
| `MONITOR` | tylko zapisuje w logu, kogo by zablokował — **domyślny** |
| `ENFORCE` | faktycznie odrzuca połączenie |

Zaczynaj od `MONITOR` i przeczytaj, co by wyleciało, zanim włączysz `ENFORCE`. `/antiproxy mode`
przełącza to do restartu, bez ruszania pliku — to przełącznik na czas incydentu.

## Komendy

| | |
|---|---|
| `/antiproxy` | statystyki: sprawdzenia, trafienia w cache, zapytania, błędy |
| `/antiproxy check <adres>` | sprawdza adres tą samą ścieżką co logowanie, z cache |
| `/antiproxy mode <MONITOR\|ENFORCE>` | przełącza tryb do restartu |
| `/antiproxy whitelist add\|remove <nick lub adres>` | wyjątki |

Wszystko pod `landmc.antiproxy.admin`.

## Cache

Dwa poziomy: mapa w pamięci i tabela w bazie. Ta druga jest **dzielona przez wszystkie proxy** —
drugie proxy sprawdzające ten sam adres znajduje wiersz zamiast wydać kolejne zapytanie z limitu.
Wpisy mają osobny czas życia dla adresów czystych i podejrzanych, a te wygasłe są sprzątane przy
starcie.

Dane połączenia z bazą bierze z placeholderów (`${LANDMC_DB_HOST}` i pozostałe), tak jak reszta
sieci — jedno miejsce dla całego networku.

## GeoIP

Bazy `GeoLite2-ASN` i `GeoLite2-Country` są pobierane i odświeżane automatycznie z MaxMind, na
darmowym kluczu licencyjnym. Świeża baza jest wczytywana w locie, bez restartu proxy.

Bez GeoIP allowlista i blacklista operatorów nie działają — zostaje samo API, czyli więcej
zapytań i wolniejsze logowanie.

## Build

```bash
cd ../landmc-platform && ./gradlew publishToMavenLocal -Pversion=1.1.0
```

```bash
./gradlew build
```

Wynik: `build/libs/landmc-antiproxy.jar`.

## Czym różni się od `skytop-antiproxy`

Przeniesione z zachowaniem logiki decyzji, z czterema zmianami:

- **baza z platformy** zamiast własnej puli Hikari, własnego ORMLite i **pięciu** sterowników
  JDBC w jarze — teraz jeden, wybierany w konfiguracji;
- **licznik naruszeń przestał przeciekać** — oryginał trzymał wpis dla każdego adresu, jaki
  kiedykolwiek został oznaczony, przez całe życie procesu. Teraz znika razem z wpisem w cache,
  bo tylko wtedy cokolwiek znaczy;
- **komunikaty w `messages.yml`** jako MiniMessage, a nie surowy tekst w `config.yml`;
- **klucz API czytany raz przy starcie**, z jasnym błędem, gdy go nie ma.
