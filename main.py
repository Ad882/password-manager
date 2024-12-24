from database.database import Database
from security import Security
from utils import generate_password, clear_terminal
from colorama import Fore, Style
import os
import getpass
import base64

def main():
    db = Database("database/passwords.db")
    security = Security(db=db)

    print(f"{Fore.BLUE}Bienvenue dans le gestionnaire de mots de passe sécurisé.{Style.RESET_ALL}")

    if not os.path.exists(security.master_password_file):
        print("Initialisation du mot de passe maître...")
        master_password = getpass.getpass("Entrez un nouveau mot de passe maître: ")
        os.remove("database/passwords.db")
        db = Database("database/passwords.db")
        security = Security(db=db)
        security.initialize_master_password(master_password)

    else:
        if not security.check_consistency():
            print(f"{Fore.RED}/!\Incohérence détectée entre le mot de passe maître et la base de données.{Style.RESET_ALL}")
            print(f"{Fore.RED}Toutes les données seront supprimées pour des raisons de sécurité.{Style.RESET_ALL}")
            os.remove("database/passwords.db")
            db = Database("database/passwords.db")
            security = Security(db=db)
            master_password = getpass.getpass("Entrez un nouveau mot de passe maître: ")
            security.initialize_master_password(master_password)
        else:
            master_password = getpass.getpass("Entrez le mot de passe maître: ")

            if not security.verify_master_password(master_password):
                print(f"{Fore.RED}Mot de passe incorrect. Fermeture du gestionnaire.{Style.RESET_ALL}")
                return

        print(f"{Fore.GREEN}Mot de passe maître correct!{Style.RESET_ALL}")

        while True:
            print("\n1. Générer un mot de passe")
            print("2. Ajouter un mot de passe")
            print("3. Récupérer un mot de passe")
            print("4. Supprimer un mot de passe")
            print("5. Lister tous les mots de passe") 
            print("6. Quitter")
            choice = input(f"{Fore.BLUE}Choisissez une option: {Style.RESET_ALL}")

            if choice == "1":
                site = input("Entrez le site ou l'application: ")
                username = input("Entrez le nom d'utilisateur: ")
                password = generate_password()
                enc_data = security.encrypt(password, master_password)
                salt_base64, encrypted_password = enc_data.split(":", 1)
                salt = base64.urlsafe_b64decode(salt_base64)
                db.add_password(site, username, encrypted_password, salt)
                print(f"{Fore.GREEN}Mot de passe généré et enregistré: {password}{Style.RESET_ALL}")


            elif choice == "2":
                site = input("Entrez le site ou l'application: ")
                username = input("Entrez le nom d'utilisateur: ")
                password = input("Entrez le mot de passe: ")
                enc_data = security.encrypt(password, master_password)
                salt_base64, encrypted_password = enc_data.split(":", 1)
                salt = base64.urlsafe_b64decode(salt_base64)
                db.add_password(site, username, encrypted_password, salt)
                print(f"{Fore.GREEN}Mot de passe enregistré!{Style.RESET_ALL}")


            elif choice == "3":
                site = input("Entrez le site ou l'application: ")
                results = db.get_password(site)

                if results:
                    print(f"{Fore.GREEN}Comptes trouvés pour le site '{site}':{Style.RESET_ALL}")
                    for index, record in enumerate(results, start=1):
                        username = record['username']
                        enc_password = record['password']
                        salt = record['salt']
                        try:
                            decoded_salt = base64.urlsafe_b64encode(salt).decode()
                            data_with_salt = decoded_salt + ":" + enc_password
                            password = security.decrypt(data_with_salt, master_password)
                            print(f"{Fore.YELLOW}Compte {index}:{Style.RESET_ALL} Nom d'utilisateur: {username}, Mot de passe: {password}")
                        except Exception as e:
                            print(f"{Fore.RED}Erreur lors du déchiffrement: {e}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}Aucun compte trouvé pour le site '{site}'.{Style.RESET_ALL}")


            elif choice == "4":
                site = input("Entrez le site ou l'application: ")
                db.delete_password(site)
                print(f"{Fore.RED}Mot de passe supprimé!{Style.RESET_ALL}")


            elif choice == "5":
                passwords = db.list_all_passwords()
                if passwords:
                    print(f"\n{Fore.YELLOW}Liste de tous les mots de passe:{Style.RESET_ALL}")
                    for site, username, enc_password, salt in passwords:
                        decoded_salt = base64.urlsafe_b64encode(salt).decode()
                        data_with_salt = decoded_salt + ":" + enc_password
                        password = security.decrypt(data_with_salt, master_password)
                        print(f"Site: {site} -- Nom d'utilisateur: {username} -- Mot de passe: {password}")
                else:
                    print(f"{Fore.RED}Aucun mot de passe enregistré.{Style.RESET_ALL}")


            elif choice == "6":
                clear_terminal()
                print(f"{Fore.RED}Gestionnaire fermé.{Style.RESET_ALL}")
                break

            else:
                print(f"{Fore.RED}Option invalide.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
