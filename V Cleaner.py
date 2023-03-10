#Developed by AnonSpenex
#E-mail address : anon.spenexploit@protonmail.com
#Discord : 𝕬𝖓𝖔𝖓𝕾𝖕𝖊𝖓𝖊𝖝#2626 

import pyttsx3
import subprocess
import os
import string
import webbrowser
import re
import time
import winsound
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

os.system("title V Cleaner")

engine = pyttsx3.init()
voices = engine.getProperty("voices")
engine.setProperty("voice", voices[1].id)

logo="""
 ██╗   ██╗   █████╗ ██╗     ███████╗ █████╗ ███╗  ██╗███████╗██████╗
 ██║   ██║  ██╔══██╗██║     ██╔════╝██╔══██╗████╗ ██║██╔════╝██╔══██╗
 ╚██╗ ██╔╝  ██║  ╚═╝██║     █████╗  ███████║██╔██╗██║█████╗  ██████╔╝
  ╚████╔╝   ██║  ██╗██║     ██╔══╝  ██╔══██║██║╚████║██╔══╝  ██╔══██╗
   ╚██╔╝    ╚█████╔╝███████╗███████╗██║  ██║██║ ╚███║███████╗██║  ██║
    ╚═╝      ╚════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝\n"""

menu = """
0: Find information about the digital footprint of a file.
1: Find information about an IP address.
2: Find information about a port.
3: Find information about a process.
4: Find information about a DLL.
5: Display all running processes in execution.
6: Display all information about network connections.
7: Determine all Windows related corruptions.
8: Perform an advanced analysis related to Windows problems.
9: Perform automatic analysis and repair of Windows related errors.
10: Activate the firewall.

UEFI-DIAGNOSTIC & ADVANDCED BOOT OPTIONS: Access the UEFI diagnostic menu and advanced boot options via a restart.
UEFI-DIAGNOSTIC: Access the UEFI diagnostic menu via a restart.
ADVANDCED BOOT OPTIONS: Access the advanced boot options via restart.
WINDOWS-UPDATE: Update Windows automatically.
BLOCK-IP: Configure a new rule blocking IP address traffic through the Windows Defender firewall.
BLOCK-PORT: Configure a new rule blocking traffic from a port through the Windows Defender firewall.
KILL-PROCESS: Stop a running process.
UAC: Modify the user control settings.
TEMP: Delete temporary files.
""" 

contact = """
CONTACT: Send a request for help to the creator of V Cleaner.
DISCORD: 𝕬𝖓𝖔𝖓𝕾𝖕𝖊𝖓𝖊𝖝#2626
"""  

antivirus = """
--------------ANTIVIRUS--------------

AVAST: Perform a analysis with Avast.
"""                               

fonctions = """
1: SHA-256
2: MD5
"""

ip_options = """
1: Find information about an IP address.
2: WHOIS.
"""

engine.say("Warning : In order to use this program in the best conditions, it is recommended to run it as an administrator.")
engine.runAndWait()

print("Warning : In order to use this program in the best conditions, it is recommended to run it as an administrator !")

time.sleep(5)
os.system("cls")

print(logo)

def options():

    option_dict = {
        "0": hash,
        "1": ip,
        "2": port,
        "3": search_process,
        "4": DLL,
        "5": display_process,
        "6": network,
        "7": corruptions,
        "8": analyse,
        "9": repair,
        "10": firewall,
        "UEFI-DIAGNOSTIC & ADVANDCED BOOT OPTIONS": uefi_diagnostic_menu_and_advanced_boot_options,
        "UEFI-DIAGNOSTIC": uefi_diagnostic,
        "ADVANDCED BOOT OPTIONS": advandced_boot_options,
        "BLOCK-IP": block_ip,
        "BLOCK-PORT": block_port,
        "WINDOWS-UPDATE": windows_update,
        "KILL-PROCESS": kill_process,
        "UAC": uac,
        "TEMP": tempory_files,
        "CONTACT": help_email,
        "AVAST": avast,
        }
    
    valid_options = option_dict.keys()
    
    while True:

        print(contact.strip())
        print(menu)
        print(antivirus.strip()+"\n")

        engine.say("What is your option ?")
        engine.runAndWait()
        
        option = input("What is your option ? : ").strip()

        os.system("cls")

        try:

            if option not in valid_options:

                frequency = 870
                duration = 1500
                winsound.Beep(frequency, duration)

                engine.say("This option is invalid. Please choose an option from the program.")
                engine.runAndWait()

                print("This option is invalid : Please choose an option from the program.")
            
                time.sleep(5)
                os.system("cls")

                print(logo)
                options()
        
            else:

                os.system("cls")
                option_dict[option]()

        except Exception as e:

            frequency = 870
            duration = 1500
            winsound.Beep(frequency, duration)

            engine.say("This option is invalid. Please choose an option from the program.")
            engine.runAndWait()

            print("This option is invalid : Please choose an option from the program.")
            
            time.sleep(5)
            os.system("cls")

            print(logo)
            options()

def hash():
    
    print("1. SHA-256\n2. MD5\n")
    
    engine.say("S-H-A-256 hash function.")
    engine.runAndWait()
    
    engine.say("MD5 hash function.")
    engine.runAndWait()
    
    engine.say("Which hash function do you want to use ?")
    engine.runAndWait()
    
    option = input("Which hash function do you want to use ? : ")

    os.system("cls")
    
    while option not in ["1", "2"]:
        
        engine.say("Please choose the first or second option.")
        engine.runAndWait()
        
        print("Warning: Please choose the first or second option.")

        engine.say("Which hash function do you want to use ?")
        engine.runAndWait()
    
        option = input("Which hash function do you want to use ? : ")

        os.system("cls")
    
    if option == "1":
        
        engine.say("You have selected the S-H-A-256 hash function.")
        engine.runAndWait()
        
        engine.say("Please enter the file path.")
        engine.runAndWait()
        
        file_path = input("Path : ")

        os.system("cls")
        
        if os.path.exists(file_path):

            engine.say("Please wait, the S-H-A-256 hash is being generated.")
            engine.runAndWait()

            progress_bar()

            os.system("cls")

            hash_value = hashlib.sha256()
            
            with open(file_path, "rb") as f:

                for chunk in iter(lambda: f.read(4096), b""):
                    
                    hash_value.update(chunk)

            print(f"The SHA-256 hash of {file_path} is {hash_value.hexdigest()}\n")

            time.sleep(10)
            os.system("cls")
            
            engine.say("Please wait, the search for information about the S-H-A-256 hash is in progress.")
            engine.runAndWait()

            progress_bar()

            os.system("cls")
            
            virustotal = f"https://www.virustotal.com/gui/file/{hash_value.hexdigest()}"
            webbrowser.open(virustotal)

            print(logo)
            options()
        
        else:
            
            engine.say("The file path does not exist.")
            engine.runAndWait()

            hash()
    
    elif option == "2":

        engine.say("You have selected the MD5 hash function.")
        engine.runAndWait()
        
        engine.say("Please enter the file path.")
        engine.runAndWait()
        
        file_path = input("Path : ")
        
        if os.path.exists(file_path):

            engine.say("Please wait, the MD5 hash is being generated.")
            engine.runAndWait()

            progress_bar()

            os.system("cls")

            hash_value = hashlib.md5()

            with open(file_path, "rb") as f:

                for chunk in iter(lambda: f.read(4096), b""):
                    
                    hash_value.update(chunk)
            
            print(f"The MD5 hash is {hash_value.hexdigest()}\n")

            time.sleep(10)
            os.system("cls")

            engine.say("Please wait while the search for information about the MD5 hash is in progress.")
            engine.runAndWait()

            virustotal = f"https://www.virustotal.com/gui/file/{hash_value.hexdigest()}"
            webbrowser.open(virustotal)

            print(logo)
            options()
        
        else:

            engine.say("The file path does not exist.")
            engine.runAndWait()

            hash()

def ip():

    engine.say("Find information about an IP address.")
    engine.runAndWait()

    engine.say("WHO-IS.")
    engine.runAndWait()

    engine.say("What is your option ?")
    engine.runAndWait()

    print(ip_options.strip()+"\n")

    ip_option = input("What is your option ? : ")

    os.system("cls")

    while ip_option not in ["1","2"]:

        frequency = 870
        duration = 1500
        winsound.Beep(frequency, duration)

        engine.say("Please choose the first or secondary option.")
        engine.runAndWait()

        print("Warning: Please choose the first or secondary option.")

        time.sleep(5)
        os.system("cls")

        print(ip_options.strip()+"\n")

        ip_option = input("What is your option ? : ")

        os.system("cls")

    if ip_option == "1":

        engine.say("What is the IP address ?")
        engine.runAndWait()

        ip = input("What is the IP address ? : ")

        os.system("cls")

        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):

            pass

        while not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):

            frequency = 870
            duration = 1500
            winsound.Beep(frequency, duration)

            engine.say("""
            Please transmit a valid IP address.
            Otherwise, this may result in a negative result.""")
            engine.runAndWait()

            print("Please transmit a valid IP address.\n""Otherwise, this may result in a negative result.")

            time.sleep(5)
            os.system("cls")

            engine.say("What is the IP address ?")
            engine.runAndWait()

            ip = input("What is the IP address ? : ")

            os.system("cls")

        engine.say(f"Please wait, the search for the IP address : {ip} information is in progress.")
        engine.runAndWait()

        progress_bar()

        os.system("cls")

        VirusTotal = f"https://www.virustotal.com/gui/ip-address/{ip}/detection"
        CheckHost = f"https://check-host.net/ip-info?host={ip}"
        webbrowser.open(VirusTotal)
        webbrowser.open(CheckHost)

        print(logo)
        options()

    elif ip_option == "2":

        engine.say("What is the IP address ?")
        engine.runAndWait()

        ip = input("What is the IP address ? : ")

        os.system("cls")

        if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):

            pass

        while not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):

            frequency = 870
            duration = 1500
            winsound.Beep(frequency, duration)

            engine.say("""
            Please transmit a valid IP address.
            Otherwise, this may result in a negative result.""")
            engine.runAndWait()

            print("Please transmit a valid IP address.\n""Otherwise, this may result in a negative result.")

            time.sleep(5)
            os.system("cls")

            engine.say("What is the IP address ?")
            engine.runAndWait()

            ip = input("What is the IP address ? : ")

            os.system("cls")

        engine.say(f"Please wait, the WHO-IS search for the IP address : {ip} is in progress.")
        engine.runAndWait()

        progress_bar()

        os.system("cls")

        WHOIS = f"https://www.whois.com/whois/{ip}"
        webbrowser.open(WHOIS)

        print(logo)
        options()

def port():
    
    engine.say("What is the port ?")
    engine.runAndWait()

    port = input("What is the port ? : ")

    os.system("cls")

    if port.isdigit() and 0 <= port <= 65536:

        pass

    while not port.isdigit():

        frequency = 870
        duration = 1500
        winsound.Beep(frequency, duration)

        engine.say("Please choose a port between 0 and 65536.")
        engine.runAndWait()

        print("Warning: Please choose a port between 0 and 65536.")

        time.sleep(5)
        os.system("cls")

        engine.say("What is the port ?")
        engine.runAndWait()

        port = input("What is the port ? : ")

        os.system("cls")

    engine.say(f"Please wait, the search for the port : {port} information is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    speedguide = f"https://www.speedguide.net/port.php?port={port}"
    webbrowser.open(speedguide)

    os.system("cls")
    
    print(logo)
    options()

def search_process():
    
    engine.say("What is the process ?")
    engine.runAndWait()

    process = input("What is the process ? : ")

    engine.say(f"Please wait, the search for process : {process} information is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    file = f"https://www.fichier.net/processus/{process}"
    webbrowser.open(file)
    
    os.system("cls")
    
    print(logo)
    options()

def DLL():
    
    engine.say("What is the DLL ?")
    engine.runAndWait()

    DLL = input("What is the DLL ? : ")

    os.system("cls")

    engine.say(f"Please wait, the search for DLL : {DLL} information is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    file = f"https://www.fichier.net/processus/{DLL}"
    webbrowser.open(file)

    os.system("cls")
    
    print(logo)
    options()

def display_process():
    
    engine.say("Please wait, the display of running processes is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    os.system("tasklist /m")
    os.system("pause > nul")
    
    os.system("cls")
    
    print(logo)
    options()
    
def network():
    
    engine.say("Please wait, displaying information about network connections is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    os.system("netstat -b")
    os.system("pause > nul")
    os.system("cls")

    os.system("netstat -ano")
    os.system("pause > nul")
    os.system("cls")

    print(logo)
    options()
    
def corruptions():
    
    engine.say("Please wait, determination of Windows-related corruption is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    subprocess.call("DISM /Online /Cleanup-Image /CheckHealth")
    os.system("pause > nul")
    
    os.system("cls")

    print(logo)
    options()

def analyse():
    
    engine.say("Please wait, an analysis of various Windows issues is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    subprocess.call("DISM /Online /Cleanup-Image /ScanHealth")
    os.system("pause > nul")

    os.system("cls")
    
    print(logo)
    options()

def repair():

    engine.say("Please wait, an analysis as well as the repair of various problems related to Windows is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    subprocess.call("DISM /Online /Cleanup-Image /RestoreHealth")

    os.system("pause > nul")
    os.system("cls")
    
    print(logo)
    options()

def firewall():
    
    engine.say("Please wait, firewall activation is in progress.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    subprocess.call("netsh advfirewall set allprofiles state on", shell=True)

    os.system("cls")
    
    print(logo)
    options()

def uefi_diagnostic_menu_and_advanced_boot_options():

    engine.say("Your computer will restart with the UEFI diagnostic menu and the advanced boot options.")
    engine.runAndWait()

    progress_bar()

    engine.say("Your computer will restart.")
    engine.runAndWait()

    os.system("shutdown /r /fw /o /f /t 00")

def uefi_diagnostic():

    engine.say("Your computer will restart with the UEFI diagnostic menu.")
    engine.runAndWait()

    progress_bar()

    engine.say("Your computer will restart.")
    engine.runAndWait()

    os.system("shutdown /r /fw /f /t 0")

def advandced_boot_options():

    engine.say("Your computer will restart with the advanced boot options.")
    engine.runAndWait()

    progress_bar()

    engine.say("Your computer will restart.")
    engine.runAndWait()

    os.system("shutdown /r /o /f /t 00")

def windows_update():

    update_output = os.popen("PowerShell -Command \"Get-WindowsUpdate\"").read()

    if update_output.strip() == "":

        engine.say("No update available, your computer is up to date.")
        engine.runAndWait()

        print("No update available, your computer is up to date.")

        os.system("control /name Microsoft.WindowsUpdate")

        time.sleep(5)
        os.system("cls")

        print(logo)
        options()

    else:

        engine.say("The search for updates is in progress.")
        engine.runAndWait()

        progress_bar()

        print("Updates :\n")
        print(update_output)

        engine.say("The installation of the updates is in progress.")
        engine.runAndWait()

        print("\nInstallation of updates :\n")
        os.system("PowerShell -Command \"Install-WindowsUpdate -AcceptAll -AutoReboot\"")

        engine.say("The opening of Windows Update is in progress, in order to verify if the updates were carried out correctly.")
        engine.runAndWait()

        os.system("control /name Microsoft.WindowsUpdate")

        os.system("pause > nul")
        os.system("cls")

    print(logo)
    options()

def block_ip():

    engine.say("What is the IP address ?")
    engine.runAndWait()

    ip = input("What is the IP ? : ")

    os.system("cls")

    if re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):

        pass

    while not re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", ip):

        frequency = 870
        duration = 1500
        winsound.Beep(frequency, duration)

        engine.say("""
        Please transmit a valid IP address.
        Otherwise, this may result in a negative result.""")
        engine.runAndWait()

        print("Please transmit a valid IP address.\nOtherwise, this may result in a negative result.")

        time.sleep(5)
        os.system("cls")

        engine.say("What is the IP address ?")
        engine.runAndWait()

        ip = input("What is the IP address ? : ")

        os.system("cls")

    engine.say("Please wait, the IP address traffic rule is being applied in the Windows Defender firewall.")
    engine.runAndWait()
        
    progress_bar()

    os.system("cls")
        
    subprocess.call(f'netsh advfirewall firewall add rule name="BLOCK-IP" dir=in interface=any action=block remoteip={ip}', shell=True)

    os.system("cls")

    print(logo)
    options()

def block_port():

    engine.say("What is the port ?")
    engine.runAndWait()

    port = input("What is the port ? : ")

    os.system("cls")

    if port.isdigit() and int(port) >= 0 and int(port) <= 65535:

        pass

    while not port.isdigit():

        frequency = 870
        duration = 1500
        winsound.Beep(frequency, duration)

        engine.say("Please choose a port between 0 and 65536.")
        engine.runAndWait()

        print("Warning: Please choose a port between 0 and 65536.")

        time.sleep(5)
        os.system("cls")

        engine.say("What is the port ?")
        engine.runAndWait()

        port = input("What is the port ? :")

        os.system("cls")

    engine.say("Please wait, the port traffic rule is being applied in the Windows Defender firewall.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    subprocess.call(f'netsh advfirewall firewall add rule dir=in action=block protocol=TCP localport={port} name="BLOCK-{port}', shell=True)

    os.system("cls")

    print(logo)
    options()

def kill_process():

    engine.say("What is the name or PID of the process ?")
    engine.runAndWait()

    process = input("What is the name or PID of the process ? :")

    os.system("cls")

    while not process.endswith(".exe"):

        frequency = 870
        duration = 1500
        winsound.Beep(frequency, duration)

        engine.say("Please transmit a valid process and add the extension : .exe of the process in question.")
        engine.runAndWait()

        print("Warning: Please transmit a valid process and add the extension: .exe of the process in question.")

        time.sleep(5)
        os.system("cls")

        engine.say("What is the name or PID of the process ?")
        engine.runAndWait()

        process = input("What is the name or PID of the process ? :")

        os.system("cls")

    engine.say("Please wait, the process is being stopped.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    os.system(f"taskkill /F /IM {process}")
    
    time.sleep(5)
    os.system("cls")

    print(logo)
    options()

def uac():

    engine.say("Please wait, the user control is being opened.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    subprocess.call("UserAccountControlSettings.exe")

    print(logo)
    options()

def tempory_files():

    engine.say("Please wait, the temporary files are being deleted.")
    engine .runAndWait()

    progress_bar()

    os.system("cls")

    os.system("del /S /F /Q %TEMP%")
    
    time.sleep(5)
    os.system("cls")

    print(logo)
    options()

def avast():

    engine.say("Do you need to download Avast ?")
    engine.runAndWait()

    avast_download = input("Do you need to download Avast ? : ")

    os.system("cls")

    if avast_download == "y":

        engine.say("Please wait, Avast is being downloaded.")
        engine.runAndWait()

        progress_bar()

        os.system("cls")

        avast_download = "https://www.avast.com/fr-fr/download-thank-you.php?product=FAV-PPC&locale=fr-fr&direct=1"
        webbrowser.open(avast_download)

        engine.say("Warning : Please install Avast before scanning.")
        engine.runAndWait()

        print("Warning : Please install Avast before scanning !")

        time.sleep(10)

        os.system(r"C:\Users\%USERNAME%\Downloads\avast_free_antivirus_setup_online.exe")

        os.system("cls")

    elif avast_download == "n":

        engine.say("Do you want to perform a complete scan of the computer and all drives ?")
        engine.runAndWait()

        scan = input("Do you want to perform a complete scan of the computer and all drives ? : ")

        os.system("cls")

        engine.say("Please wait, the complete analysis of the computer and the drives is in progress.")
        engine.runAndWait()

        progress_bar()

        if scan == "y":

            drives = []
            
            for drive in range(ord('A'), ord('Z')+1):

                drive = chr(drive)
                
                if os.path.exists(drive + ':/'):

                    drives.append(drive)

            while drives:

                for drive in drives:

                    os.chdir(r"C:\Program Files\Avast Software\Avast")
                    command = "ashCmd.exe execmd vol " + drive + ":/"
                    os.system(command)
                
                    engine.say(f"Analysis completed for : {drive} drive")
                    engine.runAndWait()
                
                    print(f"Analysis completed for : {drive} drive\n")
                    time.sleep(5)
            
                drives = []

                for drive in range(ord('A'), ord('Z')+1):

                    drive = chr(drive)

                    if os.path.exists(drive + ':/'):

                        drives.append(drive)

                engine.say("All analyses are finished.")
                engine.runAndWait()
                
                print("All analyses are finished.")
                
                time.sleep(5)
                os.system("cls")
                
                print(logo)
                options()

        elif scan == "n": 

            engine.say("What is the drive, folder or file to be analyzed ?")
            engine.runAndWait()

            avast_drive = input("What is the drive, folder or file to be analyzed ? : ")

            os.system("cls")

            valid_drive_letters = [letter + ":" for letter in string.ascii_uppercase]
            while avast_drive not in valid_drive_letters:
                
                frequency = 870
                duration = 1500
                winsound.Beep(frequency, duration)

                engine.say("Please transmit the letter of your drive, as well as the access path if it concerns a folder or file.")
                engine.runAndWait()

                print("Warning : Please transmit the letter of your drive, as well as the access path if it concerns a folder or file.")

                time.sleep(5)
                os.system("cls")

                engine.say("What is the drive, folder or file to be analyzed ?")
                engine.runAndWait()

                avast_drive = input("What is the drive, folder or file to be analyzed ? : ")

                os.system("cls")

            engine.say("Please wait, the analysis is in progress.")
            engine.runAndWait()

            progress_bar()

            os.chdir(r"C:\Program Files\Avast Software\Avast")
            subprocess.call(f"ashCmd.exe {avast_drive}", shell=True)

            os.system("cls")
            
            print(logo)
            options()

def help_email():
    
    engine.say("What is your e-mail address ?")
    engine.runAndWait()

    email = input("What is your e-mail address ? : ")
    os.system("cls")

    engine.say("""
    Warning, you need to log in with an application password !
    If you don't know how to create the password, please accept to visit Google web page that explains how to create one.""")
    engine.runAndWait()

    application_password = input("Do you want to create an application password ? : ")

    os.system("cls")

    if application_password == "y":

        engine.say("The opening of the Google web page to help you create the application password is in progress.")
        engine.runAndWait()

        progress_bar()

        os.system("cls")

        application_password_page = "https://bit.ly/3lYiaG7"
        webbrowser.open(application_password_page)

    elif application_password == "n":
        
        pass

    engine.say("What is your password ?")
    engine.runAndWait()

    password = input("What is your password ? : ")
    os.system("cls")

    recipient = "anon.spenexploit@protonmail.com"

    engine.say("Your message is being sent.")
    engine.runAndWait()

    progress_bar()

    os.system("cls")

    message = MIMEMultipart('alternative')
    message['Subject'] = "Demande d'aide à partir de V Cleaner."
    message['From'] = email
    message['To'] = recipient

    text = """Bonjour,

    Je m'adresse à vous, dans la vocation de vous solliciter afin de mieux comprendre le fonctionnement de V Cleaner.

    Cordialement."""

    part = MIMEText(text, 'plain')
    message.attach(part)

    try:

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email, password)
        server.sendmail(email, recipient, message.as_string())
        server.quit()

        engine.say("""
        The help message has been sent to the creator of V Cleaner. 
        You will soon receive a help e-mail from him.
        If not, please send him a new message.
        Please note that spamming is not allowed.
        Please do not send spam or you will be blocked immediately.""")
        engine.runAndWait()

        notification(email, password)

    except Exception as e:

        engine.say("""
        An error occurred while sending the email. 
        Please try again later.""")
        engine.runAndWait()
        
        print("An error occurred while sending the email !")

        time.sleep(5)
        os.system("cls")

        help_email()

def notification(email, password):
    
    recipient = email

    subject = "Notification of receipt of your help request : V Cleaner."
    
    text = """Please accept my best regards,

    I am pleased to inform you that I have carefully considered your request for assistance.

    You will soon receive an e-mail with the necessary information to solve your problem with V Cleaner.

    While waiting for this precious answer,

    I would like to advise you to install the different modules that are essential to the proper functioning of V Cleaner, thanks to the text document entitled : requirements.txt.

    Which can be accessed from the command prompt, by entering this command : pip install -r requirements.txt.

    I remain at your disposal for any further information : anon.spenexploit@protonmail.com

    AnonSpenex"""

    
    html = """
    
    <html>
        <body>
        <p>{}</p>
        </body>
    </html>
        """.format(text.replace('\n', '<br>'))

    message = MIMEMultipart()
    message['From'] = recipient
    message['To'] = recipient
    message['Subject'] = subject
    message.attach(MIMEText(html, 'html'))
    
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(recipient, password)
    server.sendmail(recipient, recipient, message.as_string())
    server.quit()

    engine.say("""
    You have just received an acknowledgement of your support request, it has been sent to you from your email address for security reasons.
    Please read this email, in order to better understand the different situations that will be implemented to best help you solve your problem with V Cleaner.""")
    engine.runAndWait()
    
    print(logo)
    options()

def progress_bar():

    bar_length = 20  
    total = 10

    for i in range(total + 1):

        percent = i / total
        hashes = '#' * int(percent * bar_length)
        spaces = ' ' * (bar_length - len(hashes))

        print(f'\rProgression : [{hashes}{spaces}] {int(percent * 100)}%', end='', flush=True)

        time.sleep(0.5)  

        pass

options()
