import json
import boto3
import argparse
import logging
import psycopg2

logger = logging.getLogger()

parser = argparse.ArgumentParser()
parser.add_argument('user', help='IAM user to get the effective policy for')
parser.add_argument('profile', help='base aws profile to use')
parser.add_argument('dbpassword', help='password to access database')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
args = parser.parse_args()
profile_name = args.profile
IAM_user = args.user
password = args.dbpassword

if args.verbose:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

session = boto3.Session(profile_name=profile_name)
client = session.client('iam')


#get IAM user arn
user_info = client.get_user(
    UserName = IAM_user
)
user_arn = user_info["User"]["Arn"]


#connect to database
password = args.dbpassword
conn = psycopg2.connect(
   database='effectivepolicy', user='postgres', password=password, host='localhost', port= '5432'
)
cursor = conn.cursor()


#insert IAM user to database
cursor.execute('''INSERT INTO "IAM_User"("Name", "ARN") VALUES('{0}', '{1}')'''.format(IAM_user, user_arn))
conn.commit()


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
groups = []
list_groups = client.list_groups_for_user(
    UserName=IAM_user
)
for group in list_groups['Groups']:
    groups.append(group)
    cursor.execute('''INSERT INTO "Group"("Name", "ARN") VALUES('{0}', '{1}')'''.format(group['GroupName'], group['Arn']))
    cursor.execute('''INSERT INTO "Member"("IAM_UserARN", "GroupARN") VALUES('{0}', '{1}')'''.format(user_arn, group['Arn']))
    conn.commit()

logging.info('Getting group policies for IAM user')
for g in groups:
    group_policies = client.list_attached_group_policies(
        GroupName=g['GroupName']
    )
    inline_group_policies = (client.list_group_policies(
        GroupName=g['GroupName']
    ))



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
            cursor.execute('''INSERT INTO "Role"("Name", "ARN") VALUES('{0}', '{1}')'''.format(role_name, role_arn))
            cursor.execute('''INSERT INTO "Assume"("IAM_UserARN", "RoleARN") VALUES('{0}', '{1}')'''.format(user_arn, role_arn))
            conn.commit()
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
                cursor.execute('''INSERT INTO "Policy"("ARN", "Type", "Name") VALUES('{0}', '{1}', '{2}') RETURNING "Statementid"'''.format(rpolicy['PolicyArn'], 'Role - Inline', rpolicy['PolicyName']))
                id = cursor.fetchone()[0]
                cursor.execute('''INSERT INTO "Assign"("RoleARN", "Policyid") VALUES('{0}', {1})'''.format(role_arn, id))
                conn.commit()
                cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1})'''.format(json.dumps(policy_version['Document']['Statement']), id))
                conn.commit()
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
            cursor.execute('''INSERT INTO "Role"("Name", "ARN") VALUES('{0}', '{1}')'''.format(role_name, role_arn))
            cursor.execute('''INSERT INTO "Assume"("IAM_UserARN", "RoleARN") VALUES('{0}', '{1}')'''.format(user_arn, role_arn))
            conn.commit()
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
                cursor.execute('''INSERT INTO "Policy"("ARN", "Type", "Name") VALUES('{0}', '{1}', '{2}') RETURNING "Statementid"'''.format(rpolicy['PolicyArn'], 'Role - Managed', rpolicy['PolicyName']))
                id = cursor.fetchone()[0]
                cursor.execute('''INSERT INTO "Assign"("RoleARN", "Policyid") VALUES('{0}', {1})'''.format(role_arn, id))
                conn.commit()
                cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1})'''.format(json.dumps(policy_version['Document']['Statement']), id))
                conn.commit()


# get the inline polcies' permissions and insert to database
for ipolicy in inline_policies['PolicyNames']:
    policy = client.get_user_policy(
        UserName = IAM_user,
        PolicyName = ipolicy
    )
    get_role_policies(policy) 
    cursor.execute('''INSERT INTO "Policy"("Type", "Name") VALUES('{0}', '{1}') RETURNING "Statementid"'''.format('User - Inline', ipolicy))
    id = cursor.fetchone()[0]
    cursor.execute('''INSERT INTO "Assign"("UserARN", "Policyid") VALUES('{0}', {1})'''.format(user_arn, id))
    conn.commit()
    cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1})'''.format(json.dumps(policy['PolicyDocument']['Statement']), id))
    conn.commit()


# get the managed (aws and customer) polcies' permissions and insert to database
for mpolicy in managed_policies['AttachedPolicies']:
    policy = client.get_policy(
        PolicyArn = mpolicy['PolicyArn']
    ) 
    policy_version = client.get_policy_version(
        PolicyArn = mpolicy['PolicyArn'], 
        VersionId = policy['Policy']['DefaultVersionId']
    )['PolicyVersion']
    get_role_policies(policy_version)
    cursor.execute('''INSERT INTO "Policy"("ARN", "Type", "Name") VALUES('{0}', '{1}', '{2}') RETURNING "Statementid"'''.format(mpolicy['PolicyArn'], 'User - Managed', mpolicy['PolicyName']))
    id = cursor.fetchone()[0]
    cursor.execute('''INSERT INTO "Assign"("UserARN", "Policyid") VALUES('{0}', {1})'''.format(user_arn, id))
    conn.commit()
    cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1})'''.format(json.dumps(policy_version['Document']['Statement']), id))
    conn.commit()


# get the group polcies' permissions and insert to database
if groups != []:  
    for group in groups: 
        for gpolicy in group_policies['AttachedPolicies']:
            policy = client.get_policy(
                PolicyArn = gpolicy['PolicyArn']
            )
            policy_version = client.get_policy_version(
                PolicyArn = gpolicy['PolicyArn'], 
                VersionId = policy['Policy']['DefaultVersionId']
            )['PolicyVersion']
            get_role_policies(policy_version)
            cursor.execute('''INSERT INTO "Policy"("ARN", "Type", "Name") VALUES('{0}', '{1}', '{2}') RETURNING "Statementid"'''.format(gpolicy['PolicyArn'], 'Group - Managed', gpolicy['PolicyName']))
            id = cursor.fetchone()[0]

            cursor.execute('''INSERT INTO "Assign"("GroupARN", "Policyid") VALUES('{0}', {1})'''.format(group['Arn'], id))
            conn.commit()
            cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1})'''.format(json.dumps(policy_version['Document']['Statement']), id))
            conn.commit()
        for igpolicy in inline_group_policies['PolicyNames']:
            ipolicy = client.get_group_policy(
                GroupName = group['GroupName'],
                PolicyName = igpolicy
            )
            get_role_policies(ipolicy)
            cursor.execute('''INSERT INTO "Policy"("Type", "Name") VALUES('{0}', '{1}') RETURNING "Statementid"'''.format('Group - Inline', igpolicy))
            id = cursor.fetchone()[0]

            cursor.execute('''INSERT INTO "Assign"("GroupARN", "Policyid") VALUES('{0}', {1})'''.format(group['Arn'], id))
            conn.commit()

            cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1})'''.format(json.dumps(ipolicy['PolicyDocument']['Statement']), id))
            conn.commit()


