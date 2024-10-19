Table Creation
++++++++++++++

When you create a DynamoDB table, it can take quite a while (especially if you add a few secondary index's). Instead of polling ``describe_table`` yourself,
boto3 came up with "waiters" that will do all the polling for you. The following snippet shows how to wait for a DynamoDB table to be created in an async way.

.. literalinclude:: ../../../examples/dynamodb_create_table.py
