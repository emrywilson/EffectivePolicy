import csv
import argparse
import logging
import psycopg2

logger = logging.getLogger()

parser = argparse.ArgumentParser()
parser.add_argument('database', help='database to connect to')
parser.add_argument('database_user', help='database user')
parser.add_argument('dbpassword', help='password to access database')
parser.add_argument('host', help='host for database')
parser.add_argument('port', help='port for database')
parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
args = parser.parse_args()
database = args.database
database_user = args.database_user
db_password = args.dbpassword
db_host = args.host
db_port = args.port

if args.verbose:
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

#connect to database
logging.info('Connecting to database')
password = args.dbpassword
conn = psycopg2.connect(
   database=database, user=database_user, password=db_password, host=db_host, port=db_port
)
cursor = conn.cursor()

#run rhino labs checks
def rhino_labs_priv_esc_checks(action):
    cursor.execute('''SELECT "IAM_User"."Name" AS "IAM User", "Identity"."Name" AS "Identity Name", "Identity"."Type" AS "Identity Type", "Policy"."Name" AS "Policy Name", "Policy"."Type" AS "Policy Type", "Permission"."Resource" AS "Resources" FROM "IAM_User" JOIN "Assume" ON "IAM_User"."ARN" = "Assume"."IAM_UserARN" JOIN "Identity" ON "Assume"."IdentityARN" = "Identity"."ARN" JOIN "Assign" ON "Identity"."ARN" = "Assign"."IdentityARN" JOIN "Policy" ON "Assign"."Policyid" = "Policy"."Policyid" JOIN "Statement" ON "Policy"."Statementid" = "Statement"."Statementid" JOIN "Permission" ON "Statement"."Statementid" = "Permission"."Statementid" JOIN "Action" ON "Permission"."Permissionid" = "Action"."Permissionid" WHERE "Action"."Name" LIKE %(name)s''', { 'name': '%{}%'.format(action)})
    resp = cursor.fetchall()
    for result in resp:
        print(result)

rhino_labs_priv_esc_checks("sts:AssumeRole")