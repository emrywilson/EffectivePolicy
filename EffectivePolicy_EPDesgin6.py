import json
import boto3
import argparse
import logging
import psycopg2

logger = logging.getLogger()

parser = argparse.ArgumentParser()
parser.add_argument('profile', help='base aws profile to use')
parser.add_argument('database', help='database to connect to')
parser.add_argument('database_user', help='database user')
parser.add_argument('dbpassword', help='password to access database')
parser.add_argument('host', help='host')
parser.add_argument('port', help='port')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
args = parser.parse_args()
profile_name = args.profile
database = args.database
database_user = args.database_user
db_password = args.dbpassword
db_host = args.host
db_port = args.port

if args.verbose:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

session = boto3.Session(profile_name=profile_name)
client = session.client('iam')

#connect to database
password = args.dbpassword
conn = psycopg2.connect(
   database=database, user=database_user, password=db_password, host=db_host, port=db_port
)
cursor = conn.cursor()

#get all aws users
all_users = client.list_users()
for user in all_users['Users']:
    IAM_user = user['UserName']

    #get IAM user arn
    user_info = client.get_user(
        UserName = IAM_user
    )
    user_arn = user_info["User"]["Arn"]

    #INSERT IAM user to database
    cursor.execute('''INSERT INTO "IAM_User"("Name", "ARN") VALUES('{0}', '{1}') ON CONFLICT ("ARN") DO NOTHING;'''.format(IAM_user, user_arn))
    conn.commit()

    #INSERT user identity into database
    cursor.execute('''INSERT INTO "Identity"("Name", "ARN", "Type") VALUES('{0}', '{1}', '{2}') ON CONFLICT ("ARN") DO NOTHING;'''.format(IAM_user, user_arn, "User"))
    cursor.execute('''INSERT INTO "Assume"("IAM_UserARN", "IdentityARN") VALUES('{0}', '{1}') ON CONFLICT ("IdentityARN", "IAM_UserARN") DO NOTHING;'''.format(user_arn, user_arn))
    conn.commit()


    # get inline polcies
    logging.info('Getting inline policies for ' + IAM_user)
    inline_policies = client.list_user_policies(
        UserName=IAM_user
    )

    # get all managed policies (aws and customer)
    logging.info('Getting AWS managed policies for ' + IAM_user)
    managed_policies = client.list_attached_user_policies(
        UserName=IAM_user
    )

    # get only customer managed policies
    logging.info('Getting customer managed policies for ' + IAM_user)
    customer_managed_policies = client.list_policies(
        Scope='Local'
    )

    #get groups (if any) and policies for the groups, INSERT group identity(ies) into database
    groups = []
    groups = client.list_groups_for_user(
        UserName=IAM_user
    )
    logging.info('Getting group policies for ' + IAM_user)
    for g in groups['Groups']:
        cursor.execute('''INSERT INTO "Identity"("Name", "ARN", "Type") VALUES('{0}', '{1}', '{2}') ON CONFLICT ("ARN") DO NOTHING;'''.format(g['GroupName'], g['Arn'], "Group"))
        cursor.execute('''INSERT INTO "Assume"("IAM_UserARN", "IdentityARN") VALUES('{0}', '{1}') ON CONFLICT ("IAM_UserARN", "IdentityARN") DO NOTHING;'''.format(user_arn, g['Arn']))
        conn.commit()
        group_policies = client.list_attached_group_policies(
            GroupName=g['GroupName']
        )
        inline_group_policies = (client.list_group_policies(
            GroupName=g['GroupName']
        ))

    #get each permissions in a policy's statement, INSERT into permissions table
    def extract_permissions(statement, id):
        effect = ""
        sid = ""
        action =""
        princ = ""
        rsc = ""
        cond = None
        if isinstance(statement, list):
            for stmt in statement:
                if 'Effect' in stmt:
                    effect = stmt["Effect"]
                if 'Sid' in stmt:
                    sid = stmt['Sid']
                
                if 'Principal' in stmt:
                    princ = stmt['Principal']
                if 'Resource' in stmt:
                    if not isinstance(stmt['Resource'], list):
                        rsc = list(stmt['Resource'].split(" "))
                    elif isinstance(stmt['Resource'], list):
                        rsc = stmt['Resource']
                if 'Condition' in stmt:
                    cond = stmt['Condition']
                cursor.execute('''INSERT INTO "Permission"("Effect", "Sid", "Principal", "Resource", "Condition", "Statementid") VALUES('{0}', '{1}', '{2}', ARRAY{3}, '{4}', {5}) RETURNING "Permissionid";'''.format(effect, sid, princ, rsc, json.dumps(cond), id))
                permid = cursor.fetchone()[0]
                conn.commit()
                if 'Action' in stmt:
                    if not isinstance(stmt['Action'], list):
                        action = stmt['Action']
                        cursor.execute('''INSERT INTO "Action"("Name", "Permissionid") VALUES('{0}', {1});'''.format(action, permid))
                    elif isinstance(stmt['Action'], list):
                        for action in stmt['Action']:
                            cursor.execute('''INSERT INTO "Action"("Name", "Permissionid") VALUES('{0}', {1});'''.format(action, permid))
        elif isinstance(statement, dict):
            if 'Effect' in statement:
                effect = statement['Effect']
            if 'Sid' in statement:
                sid = statement['Sid']
            if 'Principal' in statement:
                princ = statement['Principal']
            if 'Resource' in statement:
                if not isinstance(statement['Resource'], list):
                    rsc = list(statement['Resource'].split(" "))
                elif isinstance(statement['Resource'], list):
                    rsc = statement['Resource']
            if 'Condition' in statement:
                cond = statement['Condition']
            cursor.execute('''INSERT INTO "Permission"("Effect", "Sid", "Principal", "Resource", "Condition", "Statementid") VALUES('{0}', '{1}', '{2}', ARRAY{3}, '{4}', {5}) RETURNING "Permissionid";'''.format(effect, sid, princ, rsc, json.dumps(cond), id))
            permid = cursor.fetchone()[0]
            conn.commit()
            if 'Action' in statement:
                if not isinstance(statement['Action'], list):
                    action = statement['Action']
                    cursor.execute('''INSERT INTO "Action"("Name", "Permissionid") VALUES('{0}', {1});'''.format(action, permid))
                elif isinstance(statement['Action'], list):
                    for action in statement['Action']:
                        cursor.execute('''INSERT INTO "Action"("Name", "Permissionid") VALUES('{0}', {1});'''.format(action, permid))


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
                cursor.execute('''INSERT INTO "Identity"("Name", "ARN", "Type") VALUES('{0}', '{1}', '{2}') ON CONFLICT ("ARN") DO NOTHING;'''.format(role_name, role_arn, "Role"))
                cursor.execute('''INSERT INTO "Assume"("IAM_UserARN", "IdentityARN") VALUES('{0}', '{1}') ON CONFLICT ("IAM_UserARN", "IdentityARN") DO NOTHING;'''.format(user_arn, role_arn))
                conn.commit()
                logging.info('Getting role policies for roles ' + IAM_user+ ' can assume')
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
                    cursor.execute('''INSERT INTO "Policy"("ARN", "Type", "Name") VALUES('{0}', '{1}', '{2}') ON CONFLICT ("ARN") DO NOTHING RETURNING "Statementid";'''.format(rpolicy['PolicyArn'], 'Inline', rpolicy['PolicyName']))
                    resp = cursor.fetchone()
                    if resp != None:
                        id = resp[0]
                        cursor.execute('''INSERT INTO "Assign"("IdentityARN", "Policyid") VALUES('{0}', {1}) ON CONFLICT ("Policyid", "IdentityARN") DO NOTHING;'''.format(role_arn, id))
                        conn.commit()
                        cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1}) ON CONFLICT ("Statementid") DO NOTHING;'''.format(json.dumps(policy_version['Document']['Statement']), id))
                        conn.commit()
                        extract_permissions(policy_version['Document']['Statement'], id)
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
                cursor.execute('''INSERT INTO "Identity"("Name", "ARN", "Type") VALUES('{0}', '{1}', '{2}') ON CONFLICT ("ARN") DO NOTHING;'''.format(role_name, role_arn, "Role"))
                cursor.execute('''INSERT INTO "Assume"("IAM_UserARN", "IdentityARN") VALUES('{0}', '{1}') ON CONFLICT ("IAM_UserARN", "IdentityARN") DO NOTHING;'''.format(user_arn, role_arn))
                conn.commit()
                logging.info('Getting role policies for roles ' + IAM_user+ ' user can assume')
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
                    cursor.execute('''INSERT INTO "Policy"("ARN", "Type", "Name") VALUES('{0}', '{1}', '{2}')  ON CONFLICT ("ARN") DO NOTHING RETURNING "Statementid";'''.format(rpolicy['PolicyArn'], 'Managed', rpolicy['PolicyName']))
                    resp = cursor.fetchone()
                    if resp != None:
                        id = resp[0]
                        cursor.execute('''INSERT INTO "Assign"("IdentityARN", "Policyid") VALUES('{0}', {1}) ON CONFLICT ("Policyid", "IdentityARN") DO NOTHING;'''.format(role_arn, id))
                        conn.commit()
                        cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1}) ON CONFLICT ("Statementid") DO NOTHING;'''.format(json.dumps(policy_version['Document']['Statement']), id))
                        conn.commit()
                        extract_permissions(policy_version['Document']['Statement'], id)
                        


    # get the inline polcies' permissions and INSERT to database
    for ipolicy in inline_policies['PolicyNames']:
        policy = client.get_user_policy(
            UserName = IAM_user,
            PolicyName = ipolicy
        )
        get_role_policies(policy) 
        cursor.execute('''INSERT INTO "Policy"("Type", "Name") VALUES('{0}', '{1}') ON CONFLICT ("Name") DO NOTHING RETURNING "Statementid";'''.format('Inline', ipolicy))
        resp = cursor.fetchone()
        if resp != None:
            id = resp[0]
            cursor.execute('''INSERT INTO "Assign"("IdentityARN", "Policyid") VALUES('{0}', {1}) ON CONFLICT ("Policyid", "IdentityARN") DO NOTHING;'''.format(user_arn, id))
            conn.commit()
            cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1}) ON CONFLICT ("Statementid") DO NOTHING;'''.format(json.dumps(policy['PolicyDocument']['Statement']), id))
            conn.commit()
            extract_permissions(policy['PolicyDocument']['Statement'], id)
            


    # get the managed (aws and customer) polcies' permissions and INSERT to database
    for mpolicy in managed_policies['AttachedPolicies']:
        policy = client.get_policy(
            PolicyArn = mpolicy['PolicyArn']
        ) 
        policy_version = client.get_policy_version(
            PolicyArn = mpolicy['PolicyArn'], 
            VersionId = policy['Policy']['DefaultVersionId']
        )['PolicyVersion']
        get_role_policies(policy_version)
        cursor.execute('''INSERT INTO "Policy"("ARN", "Type", "Name") VALUES('{0}', '{1}', '{2}') ON CONFLICT ("ARN") DO NOTHING RETURNING "Statementid";'''.format(mpolicy['PolicyArn'], 'Managed', mpolicy['PolicyName']))
        resp = cursor.fetchone()
        if resp != None:
            id = resp[0]
            cursor.execute('''INSERT INTO "Assign"("IdentityARN", "Policyid") VALUES('{0}', {1}) ON CONFLICT ("Policyid", "IdentityARN") DO NOTHING;'''.format(user_arn, id))
            conn.commit()
            cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1}) ON CONFLICT ("Statementid") DO NOTHING;'''.format(json.dumps(policy_version['Document']['Statement']), id))
            conn.commit()
            extract_permissions(policy_version['Document']['Statement'], id)
            


    # get the group polcies' permissions and INSERT to database
    if groups != []:  
        for group in groups['Groups']: 
            for gpolicy in group_policies['AttachedPolicies']:
                policy = client.get_policy(
                    PolicyArn = gpolicy['PolicyArn']
                )
                policy_version = client.get_policy_version(
                    PolicyArn = gpolicy['PolicyArn'], 
                    VersionId = policy['Policy']['DefaultVersionId']
                )['PolicyVersion']
                get_role_policies(policy_version)
                cursor.execute('''INSERT INTO "Policy"("ARN", "Type", "Name") VALUES('{0}', '{1}', '{2}') ON CONFLICT ("ARN") DO NOTHING RETURNING "Statementid";'''.format(gpolicy['PolicyArn'], 'Managed', gpolicy['PolicyName']))
                resp = cursor.fetchone()
                if resp != None:
                    id = resp[0]
                    cursor.execute('''INSERT INTO "Assign"("IdentityARN", "Policyid") VALUES('{0}', {1}) ON CONFLICT ("Policyid", "IdentityARN") DO NOTHING;'''.format(group['Arn'], id))
                    conn.commit()
                    cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1}) ON CONFLICT ("Statementid") DO NOTHING;'''.format(json.dumps(policy_version['Document']['Statement']), id))
                    conn.commit()
                    extract_permissions(policy_version['Document']['Statement'], id)
                    
            for igpolicy in inline_group_policies['PolicyNames']:
                ipolicy = client.get_group_policy(
                    GroupName = group['GroupName'],
                    PolicyName = igpolicy
                )
                get_role_policies(ipolicy)
                cursor.execute('''INSERT INTO "Policy"("Type", "Name") VALUES('{0}', '{1}') ON CONFLICT ("Name") DO NOTHING RETURNING "Statementid";'''.format('Inline', igpolicy))
                resp = cursor.fetchone()
                if resp != None:
                    id = resp[0]
                    cursor.execute('''INSERT INTO "Assign"("IdentityARN", "Policyid") VALUES('{0}', {1}) ON CONFLICT ("Policyid", "IdentityARN") DO NOTHING;'''.format(group['Arn'], id))
                    conn.commit()
                    cursor.execute('''INSERT INTO "Statement"("WholeStatement", "Statementid") VALUES('{0}', {1}) ON CONFLICT ("Statementid") DO NOTHING;'''.format(json.dumps(ipolicy['PolicyDocument']['Statement']), id))
                    conn.commit()
                    extract_permissions(ipolicy['PolicyDocument']['Statement'], id)
                    


