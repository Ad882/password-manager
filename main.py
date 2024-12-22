from database.database import Database
from security import Security
from utils import generate_password
from colorama import Fore, Style
import os

def main():
    db = Database("database/passwords.db")
    security = Security()
    security = Security()

    print(f"{Fore.BLUE}Bienvenue dans le gestionnaire de mots de passe sécurisé.{Style.RESET_ALL}")

    if not os.path.exists(security.master_password_file):
        print("Initialisation du mot de passe maître...")
        master_password = input("Entrez un nouveau mot de passe maître: ")
        security.initialize_master_password(master_password)
    else:
        master_password = input("Entrez votre maître-mot de passe: ")

        if not security.verify_master_password(master_password):
            print("Mot de passe incorrect. Au revoir.")
            return

        print(f"{Fore.GREEN}Mot de passe maître correct!{Style.RESET_ALL}")

        while True:
            print("\n1. Générer un mot de passe")
            print("2. Ajouter un mot de passe")
            print("3. Récupérer un mot de passe")
            print("4. Supprimer un mot de passe")
            print("5. Quitter")
            choice = input(f"{Fore.BLUE}Choisissez une option: {Style.RESET_ALL}")

            if choice == "1":
                site = input("Entrez le site ou l'application: ")
                username = input("Entrez le nom d'utilisateur: ")
                password = generate_password()
                db.add_password(site, username, security.encrypt(password, master_password))
                print(f"{Fore.GREEN}Mot de passe généré et enregistré: {password}{Style.RESET_ALL}")


            elif choice == "2":
                site = input("Entrez le site ou l'application: ")
                username = input("Entrez le nom d'utilisateur: ")
                password = input("Entrez le mot de passe: ")
                db.add_password(site, username, security.encrypt(password, master_password))
                print(f"{Fore.GREEN}Mot de passe enregistré!{Style.RESET_ALL}")


            elif choice == "3":
                site = input("Entrez le site ou l'application: ")
                result = db.get_password(site)
                if result:
                    username, enc_password = result
                    password = security.decrypt(enc_password, master_password)
                    print(f"Nom d'utilisateur: {username}, Mot de passe: {password}")
                else:
                    print(f"{Fore.RED}Aucun mot de passe trouvé pour ce site.{Style.RESET_ALL}")

            elif choice == "4":
                site = input("Entrez le site ou l'application: ")
                db.delete_password(site)
                print(f"{Fore.RED}Mot de passe supprimé!{Style.RESET_ALL}")

            elif choice == "5":
                print(f"{Fore.MAGENTA}Au revoir!{Style.RESET_ALL}")
                break

            else:
                print(f"{Fore.RED}Option invalide.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
