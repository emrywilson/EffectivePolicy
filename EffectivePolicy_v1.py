import json
import boto3
import argparse
import logging

logger = logging.getLogger()

parser = argparse.ArgumentParser()
parser.add_argument('user', help='IAM user to get the effective policy for')
parser.add_argument('profile', help='base aws profile to use')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
args = parser.parse_args()
profile_name = args.profile
IAM_user = args.user

if args.verbose:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

session = boto3.Session(profile_name=profile_name)
client = session.client('iam')

# get inline polcies
logging.info('Getting inline policies for IAM user')
inline_policies = client.list_user_policies(
    UserName=IAM_user
)

# get all managed policies (aws and customer)
logging.info('Getting AWS managed policies for IAM user')
managed_policies = client.list_attached_user_policies(
    UserName=IAM_user
)

# get only customer managed policies
logging.info('Getting customer managed policies for IAM user')
customer_managed_policies = client.list_policies(
     Scope='Local'
)

#get groups (if any) and policies for the groups
groups = []
group_names = []
groups = client.list_groups_for_user(
    UserName=IAM_user
)
for group in groups['Groups']:
    group_names.append(group['GroupName'])
logging.info('Getting group policies for IAM user')
for group in group_names:
    group_policies = client.list_attached_group_policies(
        GroupName=group
    )
    inline_group_policies = (client.list_group_policies(
        GroupName=group
    ))

# open and name outfile
output_filename = IAM_user + "_effective_policy.json"
outfile = open(output_filename, "w")
outfile.write('[')

# check if any user policy has the AssumeRole action, if so, get the policies for the roles that can be assumed
def get_role_policies(policy):
    assume_role = False
    role_arn = ""
    if 'PolicyDocument' in policy:
        for key in policy['PolicyDocument']['Statement']:
            if assume_role == False:
                if key == 'Action' and policy['PolicyDocument']['Statement'][key] == 'sts:AssumeRole':
                    assume_role = True
                    continue
            if assume_role == True and key == 'Resource':
                role_arn = policy['PolicyDocument']['Statement'][key]
        role_name = role_arn.split('/')[-1]
        role_name.strip()
        if role_name != "":
            logging.info('Getting role policies for roles the IAM user can assume')
            role_policies = client.list_attached_role_policies(
                RoleName = role_name
            )
            for rpolicy in role_policies['AttachedPolicies']:
                role_policy = client.get_policy(
                    PolicyArn = rpolicy['PolicyArn']
                )
                policy_version = client.get_policy_version(
                    PolicyArn = rpolicy['PolicyArn'], 
                    VersionId = role_policy['Policy']['DefaultVersionId']
                )['PolicyVersion']
                policy_name =  '{ "' + rpolicy['PolicyName'] + '":'
                outfile.write(policy_name)  
                outfile.write(json.dumps(policy_version['Document'], indent=4))
                outfile.write('}')
                outfile.write(',')
    elif 'Document' in policy:
        for key in policy['Document']['Statement']:
            if assume_role == False:
                if key == 'Action' and policy['Statement'][key] == 'sts:AssumeRole':
                    assume_role = True
            if assume_role == True and key == 'Resource':
                role_arn = policy['Statement'][key]
        role_name = role_arn.split('/')[-1]
        role_name.strip()
        if role_name != "":
            logging.info('Getting role policies for roles the IAM user can assume')
            role_policies = client.list_attached_role_policies(
                RoleName = role_name
            )
            for rpolicy in role_policies['AttachedPolicies']:
                role_policy = client.get_policy(
                    PolicyArn = rpolicy['PolicyArn']
                )
                policy_version = client.get_policy_version(
                    PolicyArn = rpolicy['PolicyArn'], 
                    VersionId = role_policy['Policy']['DefaultVersionId']
                )['PolicyVersion']
                policy_name =  '{ "' + rpolicy['PolicyName'] + '":'
                outfile.write(policy_name)  
                outfile.write(json.dumps(policy_version['Document'], indent=4))
                outfile.write('}')
                outfile.write(',')


# get the inline polcies' permissions and add to json output
for ipolicy in inline_policies['PolicyNames']:
    policy = client.get_user_policy(
        UserName = IAM_user,
        PolicyName = ipolicy
    )
    get_role_policies(policy)  
    policy_name =  '{ "' + ipolicy + '":'
    outfile.write(policy_name)  
    outfile.write(json.dumps(policy['PolicyDocument'], indent=4))
    outfile.write('}')
    outfile.write(',')

# get the managed (aws and customer) polcies' permissions and add to json output
for mpolicy in managed_policies['AttachedPolicies']:
    policy = client.get_policy(
        PolicyArn = mpolicy['PolicyArn']
    ) 
    policy_version = client.get_policy_version(
        PolicyArn = mpolicy['PolicyArn'], 
        VersionId = policy['Policy']['DefaultVersionId']
    )['PolicyVersion']
    get_role_policies(policy_version)
    policy_name =  '{ "' + mpolicy['PolicyName'] + '":'
    outfile.write(policy_name)  
    outfile.write(json.dumps(policy_version['Document'], indent=4))
    outfile.write('}')
    outfile.write(',')

# get the group polcies' permissions and add to json output
if group_names != []:  
    for name in group_names: 
        for gpolicy in group_policies['AttachedPolicies']:
            policy = client.get_policy(
                PolicyArn = gpolicy['PolicyArn']
            )
            policy_version = client.get_policy_version(
                PolicyArn = gpolicy['PolicyArn'], 
                VersionId = policy['Policy']['DefaultVersionId']
            )['PolicyVersion']
            get_role_policies(policy_version)
            policy_name =  '{ "' + gpolicy['PolicyName'] + '":'
            outfile.write(policy_name)  
            outfile.write(json.dumps(policy_version['Document'], indent=4))
            outfile.write('}')
            outfile.write(',')
        for igpolicy in inline_group_policies['PolicyNames']:
            ipolicy = client.get_group_policy(
                GroupName = name,
                PolicyName = igpolicy
            )
            get_role_policies(ipolicy)
            policy_name =  '{ "' + igpolicy + '":'
            outfile.write(policy_name) 
            outfile.write(json.dumps(ipolicy['PolicyDocument'], indent=4))  
            outfile.write('}')  
            outfile.write(',')
            

outfile.write('{}')
outfile.write(']')

