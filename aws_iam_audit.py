import boto3 
import json
from colorama import Fore, Style , init


class aws_iam_audit:
    def __init__(self):
        self.iam_client = boto3.client('iam')
        self.audit_results = []

    def get_users(self):
        """
        Retrieve a list of IAM users.

        Returns:
            list: A list of dictionaries where each dictionary contains information about an IAM user.
        """
        return self.iam_client.list_users()['Users']
    


    def get_keys(self, username):
        """
        Retrieve a list of access keys.

        Returns:
            list: A list of dictionaries where each dictionary contains information about an access key.
        """
        return self.iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
    

    def get_mfa_status(self, username):         
        """
        Check the MFA status of a given IAM user.

        Args:
            username (str): The username of the IAM user to check.

        Returns:
            str: A string indicating the MFA status of the user. The string will be either
                "Enabled" (green) or "Disabled" (red).
        """
        if self.iam_client.list_mfa_devices(UserName=username)['MFADevices']:
             return f"{Fore.GREEN}Enabled{Style.RESET_ALL}"
        else:
             return f"{Fore.RED}Disabled{Style.RESET_ALL}"
    def save_to_file(self, filename="iam_audit.json"):
        """Save audit results to a JSON file."""
        if not self.audit_results:
            print("No audit results to save. Run the audit first.")
            return

        with open(filename, 'w') as f:
            json.dump(self.audit_results, f, indent=4, default=str)
        print(f"Audit results saved to {filename}")

    
    def print_results(self):
        """Print audit results to the console."""
        if not self.audit_results:
            print("No audit results to display. Run the audit first.")
            return
        
        for user_data in self.audit_results:
            print(f"\nUser: {user_data['UserName']}")
            print(f"    - MFA Status: {user_data['MFAStatus']}")
            for key in user_data['AccessKeys']:
                print(f"    - Access Key ID: {key['AccessKeyId']}")
                print(f"      Status: {key['Status']}")
                print(f"      Last Used Date: {key['LastUsedDate']}")
                print(f"      Last Used Region: {key['Region']}")
                print(f"      Last Used Service: {key['Service']}")
        print("\nAudit results displayed.")
        

    def run_audit(self):
        """Perform IAM audit for each user, checking MFA and access key information."""
        self.audit_results = []  # Reset results each time the audit is run
        users = self.get_users()
        
        for user in users:
            username = user['UserName']
            user_data = {
                "UserName": username,
                "MFAStatus": self.get_mfa_status(username),
                "AccessKeys": []
            }
            
            # Retrieve access keys for the user
            access_keys = self.get_keys(username)
            
            for key in access_keys:
                access_key_id = key['AccessKeyId']
                
                # Retrieve last used information for each access key
                last_used_info = self.iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                
                # Extract last used date, region, and service if available
                last_used_date = last_used_info['AccessKeyLastUsed'].get('LastUsedDate', 'Never used')
                region = last_used_info['AccessKeyLastUsed'].get('Region', 'N/A')
                service = last_used_info['AccessKeyLastUsed'].get('ServiceName', 'N/A')
                
                # Append access key details to user data
                user_data["AccessKeys"].append({
                    "AccessKeyId": access_key_id,
                    "Status": key['Status'],
                    "LastUsedDate": last_used_date,
                    "Region": region,
                    "Service": service
                })
            
            # Add user data to audit results
            self.audit_results.append(user_data)
        
        print("Audit complete.")
        self.print_results()