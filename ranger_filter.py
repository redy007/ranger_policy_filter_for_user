# author: Miroslav Sivon
import requests
import json
import xml.etree.ElementTree as ET
import ConfigParser
from requests_kerberos import HTTPKerberosAuth, REQUIRED, DISABLED, OPTIONAL


def ranger_policies(user, url):
    kerberos_auth = HTTPKerberosAuth(mutual_authentication=REQUIRED, sanitize_mutual_error_response=False)

    params = (
        ('name', user),
    )

    users_url = url + '/service/xusers/users'
    policy_url = url + '/service/public/api/policy'
    response = requests.get(users_url, params=params, auth=kerberos_auth)
    response_policy = requests.get(policy_url, params=params, auth=kerberos_auth)

    if response.status_code < 400:
        # print(response.content)
        root = ET.fromstring(response.content)

        # get all all user's groups into the list
        group_name_list = [child.text for child in root[6].iter('groupNameList')]
        print("username: " + user + " his groups: " + str(group_name_list))
        print()
        # used to ban duplicity
        policy_used = []

        # look for groups in policies owned by user
        if response_policy.status_code < 400:
            policy_data = json.loads(response_policy.text)
            policy_tags = policy_data["vXPolicies"]

            # check each policy record
            for policy_tag in policy_tags:
                # check against user's owned groups
                for group in group_name_list:
                    tag_groups = policy_tag["permMapList"][0]["groupList"]
                    tag_user_list = policy_tag["permMapList"][0]["userList"]
                    # if user's group match to policy group and print it
                    if group in tag_groups or user in tag_user_list:
                        if policy_tag["id"] in policy_used:
                            continue
                        policy_used.append(policy_tag["id"])
                        if policy_tag["isEnabled"]:
                            if policy_tag["repositoryType"] == "hive":
                                print("id: " + str(policy_tag["id"]) + " type: " + policy_tag["repositoryType"] + " path: "
                                      + policy_tag["resourceName"] + " database: " + policy_tag["databases"] + " table: "
                                      + policy_tag["tables"] + " column : " + policy_tag["columns"] + " recursive: "
                                      + str(policy_tag["isRecursive"]) + " permissions: "
                                      + str(policy_tag["permMapList"][0]["permList"]))
                            else:
                                print("id: " + str(policy_tag["id"]) + " type: " + policy_tag["repositoryType"] + " path: "
                                      + policy_tag["resourceName"] + " recursive: " + str(policy_tag["isRecursive"])
                                      + " permissions: " + str(policy_tag["permMapList"][0]["permList"]))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('Add user id - e.g. p901son')
        exit(1)

    user = str(sys.argv[1])

    Config = ConfigParser.ConfigParser()
    Config.read("settings.ini")
    Name = ConfigSectionMap("Environment")['url']
    ranger_policies(user, url)
