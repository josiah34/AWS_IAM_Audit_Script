from aws_iam_audit import aws_iam_audit

def main_menu():
    audit = aws_iam_audit()
    
    while True:
        print("\nIAM Audit Program")
        print("1. Run IAM Audit")
        print("2. Save Audit Results to File")
        print("3. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            audit.run_audit()
        elif choice == "2":
            if audit.audit_results:
                audit.save_to_file()
            else:
                print("No audit results to save. Run the audit first.")
        elif choice == "3":
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
