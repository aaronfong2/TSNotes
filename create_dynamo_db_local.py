#!venv/bin/python

import boto3

dynamodb=boto3.client('dynamodb',endpoint_url='http://localhost:8000')

attr_def=[{'AttributeName':'msg_id','AttributeType':'S'}]
key_schema=[{'AttributeName':'msg_id','KeyType':'HASH'}]
tput={'ReadCapacityUnits':1,'WriteCapacityUnits':1}

table=dynamodb.create_table(AttributeDefinitions=attr_def,TableName='TSNotes',KeySchema=key_schema,ProvisionedThroughput=tput)
