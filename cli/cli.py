import hvcli
import colorama
from colorama import Fore, Style

def main():
    # Initialize colorama on Windows so ANSI codes work
    colorama.init(autoreset=True)

    print(Fore.CYAN + "=== Hypervisor CLI ===")

    # Initial Ping
    status = hvcli.Ping()
    if status == 0:
        print(Fore.GREEN + "[+] Connected to hypervisor.\n")
    else:
        print(Fore.RED + f"[-] Ping failed. Status code: {status}")
        return

    while True:
        print("Menu:")
        print("  1) Ping hypervisor")
        print("  2) Query VMX stats")
        print("  3) Terminate VMX")
        print("  4) Exit")

        choice = input("\nSelect an option: ")

        if choice == "1":
            status = hvcli.Ping()
            if status == 0:
                print(Fore.GREEN + "[+] Ping returned success (0)\n")
            else:
                print(Fore.RED + f"[-] Ping returned status: {status}\n")

        elif choice == "2":
            try:
                stats = hvcli.query_stats()
                print(stats)
            except RuntimeError as e:
                print(Fore.RED + f"[-] Error querying stats: {e}")

        elif choice == "3":
            status = hvcli.Terminate()
            if status == 0:
                print(Fore.GREEN + "[+] Terminate returned success (0)\n")
            else:
                print(Fore.RED + f"[-] Terminate returned status: {status}\n")

        elif choice == "4":
            print(Fore.CYAN + "[+] Exiting CLI.\n")
            break

        else:
            print(Fore.RED + "[-] Unknown option.\n")

if __name__ == "__main__":
    main()
