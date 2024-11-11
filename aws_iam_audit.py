import boto3 
from colorama import Fore, Style , init


class aws_iam_audit:
    def __init__(self):
        self.iam_client = boto3.client('iam')

    def get_users(self):
        """
        Retrieve a list of IAM users.

        Returns:
            list: A list of dictionaries where each dictionary contains information about an IAM user.
        """
        return self.iam_client.list_users()['Users']
    


    def get_keys(self):
        """
        Retrieve a list of access keys.

        Returns:
            list: A list of dictionaries where each dictionary contains information about an access key.
        """
        return self.iam_client.list_access_keys()['AccessKeyMetadata']
    

    def get_mfa_status(self, username):
         if self.iam_client.list_mfa_devices(UserName=username)['MFADevices']:
             return f"{Fore.GREEN}Enabled{Style.RESET_ALL}"
         else:
             return f"{Fore.RED}Disabled{Style.RESET_ALL}"


    def iam_audit(self):
        users = self.get_users()
        for user in users:
            username = user['UserName']
            print(f"User: {username}")
            
            # Check if MFA is enabled for the user
            mfa_status = self.get_mfa_status(username)
            print(f"    - MFA Status: {mfa_status}")
            print("\n")
            
            # Use get_keys to retrieve access keys for each user
            access_keys = self.get_keys()
            
            for key in access_keys:
                access_key_id = key['AccessKeyId']
                print(f"    - Access Key ID: {access_key_id}")
                print(f"    - Access Key Status: {key['Status']}")
                
                # Retrieve last used information for each access key
                last_used_info = self.iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                
                # Extract and print last used date, region, and service if available
                if 'LastUsedDate' in last_used_info['AccessKeyLastUsed']:
                    last_used_date = last_used_info['AccessKeyLastUsed']['LastUsedDate']
                    region = last_used_info['AccessKeyLastUsed'].get('Region', 'N/A')
                    service = last_used_info['AccessKeyLastUsed'].get('ServiceName', 'N/A')
                    print(f"    - Last Used Date: {last_used_date}")
                    print(f"    - Last Used Region: {region}")
                    print(f"    - Last Used Service: {service}")
                    print("\n")
                else:
                    print("    - Last Used: Never used")
                    print("\n")
            print("\n")


# Run the audit
if __name__ == "__main__":
    audit = aws_iam_audit()
    audit.iam_audit()
