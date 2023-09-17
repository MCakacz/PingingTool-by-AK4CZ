import tkinter as tk
from tkinter import simpledialog
from tkinter import messagebox
from ftplib import FTP
import os
import logging
import socket
from datetime import datetime
import subprocess
import threading
from tkinter import ttk
import sys
import re
from cryptography.fernet import Fernet
import psutil
from GPUtil import GPU
import GPUtil

#====================================================================================================================================================
#====================================================================[MEGA WAŻNE]====================================================================
#====================================================================================================================================================

# Tworzenie folderu z logami w razie gdyby nie istniał
if not os.path.exists("logs"):
    os.makedirs("logs")

# Ustalanie sposobu tworzenia nazwy pliku logującego dla każdej sesji skryptu
log_filename = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_") + socket.gethostname() + ".log"
logging.basicConfig(filename=os.path.join("logs", log_filename), level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

#====================================================================================================================================================
#====================================================================[MEGA WAŻNE]====================================================================
#====================================================================================================================================================


# Funkcja do uzyskiwania hasła od użytkownika
def get_password(prompt):
    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring("Input", prompt, show='*')
    return password

# Sprawdzenie, czy plik info.env istnieje
if not os.path.exists("info.env"):
    # Pobieranie hasła do Aplikacji
    haslo = get_password("Podaj hasło do Aplikacji:")
    logging.info("Pomyślnie zapisano hasło do aplikacji")

    # Pobieranie hasła FTP
    haslo_ftp = get_password("Podaj hasło FTP:")
    logging.info("Pomyślnie zapisano hasło do FTP")

    # Pobieranie użytkownika FTP
    uzytkownik_ftp = get_password("Podaj użytkownika FTP:")
    logging.info("Pomyślnie zapisano użytkownika FTP")

    # Pobieranie hosta FTP
    host_ftp = get_password("Podaj hosta FTP:")
    logging.info("Pomyślnie zapisano hosta FTP")

    # Wygeneruj klucz i zapisz go do pliku key.env
    klucz = Fernet.generate_key()
    logging.info("pomyślnie wygenerowano klucz szyfrowania")
    with open("key.env", "wb") as key_file:
        key_file.write(klucz)
        logging.info("pomyślnie zapisano klucz szyfrowania do pliku key.env")


    # Szyfruj dane i zapisz je do pliku info.env
    f = Fernet(klucz)
    haslo_zaszyfrowane = f.encrypt(haslo.encode())
    logging.info("pomyślnie zaszyfrowano hasło do aplikacji")
    haslo_ftp_zaszyfrowane = f.encrypt(haslo_ftp.encode())
    logging.info("pomyślnie zaszyfrowano hasło do FTP")
    uzytkownik_ftp_zaszyfrowane = f.encrypt(uzytkownik_ftp.encode())
    logging.info("pomyślnie zaszyfrowano użytkownika FTP")
    host_ftp_zaszyfrowany = f.encrypt(host_ftp.encode())
    logging.info("pomyślnie zaszyfrowano hosta FTP")

    with open("info.env", "wb") as info_file:
        info_file.write(haslo_zaszyfrowane + b"\n")
        info_file.write(haslo_ftp_zaszyfrowane + b"\n")
        info_file.write(uzytkownik_ftp_zaszyfrowane + b"\n")
        info_file.write(host_ftp_zaszyfrowany + b"\n")
        logging.info("pomyślnie zapisano zaszyfrowane dane do pliku info.env")
else:
    # Odczytaj klucz z pliku key.env
    with open("key.env", "rb") as key_file:
        klucz = key_file.read()
        logging.info("pomyślnie odczytano dane zapisanego wcześniej klucza szyfrującego")

    f = Fernet(klucz)

    # Odczytaj zaszyfrowane dane z pliku info.env i odszyfruj je
    with open("info.env", "rb") as info_file:
        haslo_zaszyfrowane = info_file.readline().strip()
        haslo_ftp_zaszyfrowane = info_file.readline().strip()
        uzytkownik_ftp_zaszyfrowane = info_file.readline().strip()
        host_ftp_zaszyfrowany = info_file.readline().strip()
        logging.info("pomyślnie odczytano wszystkie zaszyfrowane pliki...")

    haslo = f.decrypt(haslo_zaszyfrowane).decode()
    logging.info("pomyślnie odszyfrowano dane zaszyfrowanego hasła do aplikacji")
    haslo_ftp = f.decrypt(haslo_ftp_zaszyfrowane).decode()
    logging.info("pomyślnie odszyfrowano dane zaszyfrowanego hasła do FTP")
    uzytkownik_ftp = f.decrypt(uzytkownik_ftp_zaszyfrowane).decode()
    logging.info("pomyślnie odszyfrowano dane zaszyfrowanego użytkownika do FTP")
    host_ftp = f.decrypt(host_ftp_zaszyfrowany).decode()
    logging.info("pomyślnie odszyfrowano dane zaszyfrowanego hosta do FTP")





# Ścieżka do folderu z logami
log_folder = "logs"

# Liczenie plików .log w folderze
log_files_count = len([f for f in os.listdir(log_folder) if f.endswith('.log')])

# Zapisanie informacji do logów
logging.info("Dotychczasowo uruchomiono program %d razy.", log_files_count)
logging.info(" ")


import platform

# Informacje o procesorze
cpu_info = f"Model procesora: {platform.processor()}"

# Informacje o pamięci RAM
ram_info = psutil.virtual_memory()

logging.info("Informacje o CPU:")
logging.info(cpu_info)
logging.info(f"Ilość rdzeni CPU: {psutil.cpu_count(logical=False)}")
logging.info(f"Ilość wątków CPU: {psutil.cpu_count(logical=True)}")

logging.info("\nInformacje o RAM:")
logging.info(f"Całkowita pamięć RAM: {ram_info.total / (1024 ** 3):.2f} GB")
logging.info(f"Dostępna pamięć RAM: {ram_info.available / (1024 ** 3):.2f} GB")


try:
    GPUs = GPUtil.getGPUs()
    if GPUs:
        gpu_info = GPUs[0]
        logging.info("\nInformacje o GPU:")
        logging.info(f"Nazwa GPU: {gpu_info.name}")
        logging.info(f"Pamięć VRAM GPU: {gpu_info.memoryTotal} MB")
        logging.info(" ")
    else:
        logging.info("\nBrak dostępnych GPU.")
        logging.info(" ")
except Exception as e:
    logging.info(f"\nBłąd pobierania informacji o GPU: {str(e)}")
    logging.info(" ")



# Dodawanie Adresu IP urządzenia hostującego działanie skryptu na początek każdego loga
ip_address = socket.gethostbyname(socket.gethostname())
logging.info("Adres IP komputera: %s", ip_address)

#=======================================================================================================================
#====================================[ Sprawdzanie aktualności pobranych bibliotek ]====================================
#=======================================================================================================================

# Lista importowanych bibliotek
imported_libraries = [
    'GPUtil',
    'psutil',
]

for library in imported_libraries:
    try:
        # Pobranie wersji biblioteki
        version_info = subprocess.check_output([sys.executable, '-m', 'pip', 'show', library])
        version_info = version_info.decode('utf-8').strip().split('\n')

        # Wersja i stan aktualizacji
        version = next(line for line in version_info if line.startswith('Version:')).split(': ')[1].strip()
        up_to_date = next((line for line in version_info if line.startswith('Up to date:')), 'Up to date: No information provided').split(': ')[1].strip()

        # Logowanie informacji o bibliotece
        log_message = f"Library: {library}, Version: {version}, Up to date: {up_to_date}"
        logging.info(log_message)

    except Exception as e:
        # Obsługa błędów
        log_message = f"Library: {library}, Error: {str(e)}"
        logging.warning(log_message)


#========================================================================================================
#====================================[ Dane logowania na serwer FTP ]====================================
#========================================================================================================
ftp_host = host_ftp
logging.info("Pomyślnie odczytano zaszyfrowane dane odnośnie FTP (host)")
ftp_user = uzytkownik_ftp
logging.info("Pomyślnie odczytano zaszyfrowane dane odnośnie FTP (user)")
ftp_password = haslo_ftp
logging.info("Pomyślnie odczytano zaszyfrowane dane odnośnie FTP (password)")
#========================================================================================================
#========================================================================================================
#========================================================================================================


# Logowanie na serwer FTP
try:
    ftp = FTP(ftp_host)
    ftp.login(user=ftp_user, passwd=ftp_password)
    logging.info("Zalogowano na serwerze FTP.")
except Exception as e:
    logging.error("Błąd logowania na serwerze FTP: %s", str(e))
    logging.error("Kontynuowanie funkcjonalności skryptu bez stałego łącza z serwerem ftp jest niemożliwe, zamykanie programu...")
    os._exit()

# Ścieżka do folderu logs na serwerze FTP
remote_logs_folder = "logs"

# Sprawdzenie czy folder logs istnieje na serwerze ftp i jeżeli nie to tworzenie go
if remote_logs_folder not in ftp.nlst():
    ftp.mkd(remote_logs_folder)

# Nadpisywanie ścieżki do pliku logującego na serwerze FTP (w folderze logs)
remote_file_path = f"{remote_logs_folder}/{log_filename}"

# Definiowanie Hasła
prawidlowe_haslo = haslo

# Tworzenie okna z panelem logowania
okno_logowania = tk.Tk()
okno_logowania.title("Logowanie")
logging.info("Pomyślnie utworzono okno z panelem logowania")

# Ustaw rozmiar i położenie okna na środku ekranu
szerokosc_okna = 400
logging.info("Pomyślnie ustalono szerokość okna logowania")
wysokosc_okna = 200
logging.info("Pomyślnie ustalono wysokość okna logowania")
szerokosc_ekranu = okno_logowania.winfo_screenwidth()
wysokosc_ekranu = okno_logowania.winfo_screenheight()
x = (szerokosc_ekranu - szerokosc_okna) // 2
y = (wysokosc_ekranu - wysokosc_okna) // 2
okno_logowania.geometry(f"{szerokosc_okna}x{wysokosc_okna}+{x}+{y}")
logging.info("Pomyślnie zakończono obliczanie procesu matematycznego dla ustawień graficznych okna logowania")

# Funkcja obsługująca zamknięcie okna
def zamknij_okno():
    logging.info("Zamknięto okno logowania")
    okno_logowania.destroy()
    ftp.quit()  # Rozłącz się z serwerem FTP
    logging.info("Sukces! Rozłączono z serwerem FTP")
    sys.exit()  # Zamyka cały program

# Obsługa zamknięcia okna logowania
okno_logowania.protocol("WM_DELETE_WINDOW", zamknij_okno)

# Zmienna do śledzenia liczby prób logowania
liczba_prob = 3  # <--- Ustaw maksymalną liczbę prób

# Funkcja do sprawdzania hasła
def sprawdz_haslo(event=None):
    global liczba_prob
    wprowadzone_haslo = entry.get()
    
    if wprowadzone_haslo == prawidlowe_haslo:
        messagebox.showinfo("Sukces", "Zalogowano pomyślnie!")
        logging.info("Sukces", "Zalogowano pomyślnie!")
        okno_logowania.destroy()  # Zamknij okno po poprawnym zalogowaniu
        
    else:
        liczba_prob -= 1
        if liczba_prob > 0:
            messagebox.showerror("Błąd", f"Błędne hasło. Pozostałe próby: {liczba_prob}")
            logging.error(f"Błędne hasło. Pozostałe próby: {liczba_prob}")
        else:
            messagebox.showerror("Błąd", "Brak pozostałych prób. Aplikacja zostanie zamknięta.")
            logging.fatal("Brak pozostałych prób. Aplikacja zostanie zamknięta.")
            with open(os.path.join("logs", log_filename), "rb") as file:
                ftp.storbinary(f"STOR {remote_file_path}", file)
            ftp.quit()
            os._exit(0)

# Napis na oknie
label = tk.Label(okno_logowania, text="Wprowadź hasło:")
label.pack()

# Pole do wprowadzenia hasła
entry = tk.Entry(okno_logowania, show="*")  # Hasło jest wyświetlane jako "*"
logging.info("Pomyślnie włączono usługę graficznego szyfrowania hasła")
entry.pack()
entry.focus_set()  # Ustaw fokus na polu do wprowadzania hasła

# Tworzenie przycisku do zatwierdzania hasła
button = tk.Button(okno_logowania, text="Zaloguj", command=sprawdz_haslo)
logging.info("Pomyślnie utworzono przycisk do zatwierdzania hasła")

# Ustalenie położenia przycisku na środku okna
button.pack()
okno_logowania.update_idletasks()
button_width = button.winfo_width()
entry_width = entry.winfo_width()
x_button = (szerokosc_okna - button_width) // 2
x_entry = (szerokosc_okna - entry_width) // 2
button.place(x=175, y=100)  # Dostosuj wartość 'y' do położenia przycisku
entry.place(x=140, y=50)    # Dostosuj wartość 'y' do położenia pola wprowadzania hasła


# Obsługa naciśnięcia klawisza Enter
entry.bind("<Return>", sprawdz_haslo)
logging.info("Pomyślnie aktywowano funkcję naciśnięcia klawisza enter w panelu logowania")

# Rozpoczęcie głównej pętli Tkinter
okno_logowania.mainloop()
logging.info("Pomyślnie rozpoczęto główną pętlę Tkinter")

ftp.quit()
logging.info("Sukces! Rozłączono z serwerem FTP")



#==================================================================================================================================================================
#==================================================[KONIEC LOGOWANIA, OTWIERANIE FAKYTYCZNEGO NARZĘDZIA]============================================================
#==================================================================================================================================================================


logging.info("==============[OTWORZONO NARZĘDZIE WYWOŁUJĄCE CALLBACKI]==============")

ping_console_output = []
output_text = None  

def detect_ip_format(ip_address):
    # Sprawdź, czy adres jest w formacie IPv4
    ipv4_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_pattern, ip_address):
        return "IPv4"

    # Sprawdź, czy adres jest w formacie IPv6
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    if re.match(ipv6_pattern, ip_address):
        return "IPv6"

    # Sprawdź, czy adres jest w formacie IPv4 w notacji CIDR
    ipv4_cidr_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    if re.match(ipv4_cidr_pattern, ip_address):
        return "IPv4 CIDR"

    # Sprawdź, czy adres jest w formacie IPv6 w skróconej formie
    ipv6_short_pattern = r'^([0-9a-fA-F]{1,4}::?)+$'
    if re.match(ipv6_short_pattern, ip_address):
        return "IPv6 Short"

    # Sprawdź, czy adres jest w formacie IPv4-mapped IPv6
    ipv4_mapped_ipv6_pattern = r'^::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ipv4_mapped_ipv6_pattern, ip_address):
        return "IPv4-mapped IPv6"

    # Jeśli nie pasuje do żadnego z powyższych, zwróć "Nieznany format"
    return "Nieznany format"

# Funkcja do obsługi przycisku "Ping"
def ping_ip():
    ip_address = ip_entry.get()
    num_pings = int(ping_count_var.get())

    # Sprawdź format adresu IP
    ip_format = detect_ip_format(ip_address)
    logging.info("wprowadzony format ip to: ", ip_format)

    if ip_format == "Nieznany format":
        messagebox.showerror("Błąd", "Błędnie wprowadzony adres IP. Spróbuj ponownie.")
        logging.error("Błędnie wprowadzono adres IP/nie udało się odczytać formatu")
        return

    output_text.delete(1.0, tk.END)  # Wyczyść pole tekstowe przed rozpoczęciem testów
    progress_bar["value"] = 0
    progress_bar["maximum"] = num_pings

    def ping_thread():
        try:
            for _ in range(num_pings):
                process = subprocess.Popen(["ping", ip_address], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                for line in process.stdout:
                    line = line.strip()  # Usuń białe znaki z początku i końca linii
                    ping_console_output.append(line)  # Dodaj linię do listy
                    update_output_text(line)  # Zaktualizuj pole tekstowe
                    
                process.wait()

                if process.returncode == 0:
                    response_text = f"Operacja ping zakończona z kodem wyjścia {process.returncode}"
                else:
                    response_text = f"Błąd: Operacja ping zakończona z kodem wyjścia {process.returncode}"

                ping_console_output.append(response_text)
                update_output_text(response_text)

                # Dodaj znaki nowej linii między wynikami ping
                ping_console_output.append('')
                update_output_text('')
                
                progress_bar["value"] += 1

        except Exception as e:
            ping_console_output.append(f"Błąd: {str(e)}")
            update_output_text(f"Błąd: {str(e)}")

    ping_thread = threading.Thread(target=ping_thread)
    ping_thread.start()

def update_output_text(new_text):
    global output_text  
    if output_text:
        # Przetwórz wyniki ping i zaktualizuj pole tekstowe
        formatted_output = "\n".join(ping_console_output)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, formatted_output)

# Tworzenie okna aplikacji pingującej
pingtool = tk.Tk()
pingtool.title("Ping Tool by AK4CZ")
logging.info("utworzono okno Ping Tool by AK4CZ")

# Powiększenie szerokości i wysokości okna o 50% zmień wartości "0,5" poniżej aby zmienić
window_width = int(pingtool.winfo_screenwidth() * 0.5)
window_height = int(pingtool.winfo_screenheight() * 0.5)
pingtool.geometry(f"{window_width}x{window_height}")

# Zablokowanie możliwości zmieniania wielkości okna
pingtool.resizable(False, False)
logging.info("Zablokowano możliwość zmieniania wielkości okna")

# Wyśrodkowanie okna na ekranie
x_pos = (pingtool.winfo_screenwidth() // 2) - (window_width // 2)
y_pos = (pingtool.winfo_screenheight() // 2) - (window_height // 2)
pingtool.geometry(f"+{x_pos}+{y_pos}")
logging.info("Wyśrodkowano okno aplikacji docelowej")

# Tworzenie etykiety i pola do wprowadzenia IP
ip_label = tk.Label(pingtool, text="Wprowadź adres IP:")
ip_label.pack()
ip_entry = tk.Entry(pingtool)
ip_entry.pack()
logging.info("Utworzono etykiety i pola do wprowadzenia IP")

# Tworzenie etykiety i pola do wprowadzenia liczby prób pingowania
ping_count_label = tk.Label(pingtool, text="Liczba serii prób :")
ping_count_label.pack()
ping_count_var = tk.StringVar()
ping_count_var.set("1")
ping_count_entry = tk.Entry(pingtool, textvariable=ping_count_var)
ping_count_entry.pack()
logging.info("Utworzono etykiety i pola do wprowadzenia liczby prób pingowania")

# Tworzenie przycisku "Ping"
ping_button = tk.Button(pingtool, text="Testuj!", command=ping_ip)
ping_button.pack()
logging.info("Utworzono Przycisk Ping(Testuj!)")

# Tworzenie pola tekstowego do wyświetlania wyników (bez paska przewijania)
output_text = tk.Text(pingtool, wrap=tk.WORD)
logging.info("Utworzono pole tekstowe do wyświetlania wyników bez paska przewijania")
output_text.pack(fill=tk.BOTH, expand=True)  # Wypełniaj całą dostępną przestrzeń
logging.info("Zaimplementowano wypełnienie całej dostępnej pozostałej przestrzeni przez pole tekstowe do wyświetlania wyników")

# Tworzenie paska postępu
progress_bar = ttk.Progressbar(pingtool, orient="horizontal", mode="determinate", length=800)
progress_bar.pack()
logging.info("Utworzono pasek dostępu")

# Uruchom główną pętlę Tkinter
pingtool.mainloop()
logging.info("Uruchomiono główną pętlę Tkinter")

logging.info("====================[OutPut Konsoli PingTool]====================")
logging.info(ping_console_output)

try:
    ftp = FTP(ftp_host)
    ftp.login(user=ftp_user, passwd=ftp_password)
except Exception as e:
    logging.error("Błąd ponownego logowania na serwerze FTP (nie udało się wysłać logu na serwer ftp): %s", str(e))

# Przesłanie pliku logującego na serwer FTP
with open(os.path.join("logs", log_filename), "rb") as file:
    ftp.storbinary(f"STOR {remote_file_path}", file)

# Zakończenie sesji FTP
ftp.quit()
logging.info("Sukces! Rozłączono ponownie z serwerem FTP")
logging.info("Zamykanie programu...")
