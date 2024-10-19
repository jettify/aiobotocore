

Batch Insertion
+++++++++++++++

Now if you have a massive amount of data to insert into Dynamo, I would suggest using an EMR data pipeline (theres even an example for exactly this). But
if you stubborn, here is an example of inserting lots of items into Dynamo (it's not really that complicated once you've read it).

What the code does is generates items (e.g. item0, item1, item2...) and writes them to a table "test" against a primary partition key called "pk"
(with 5 read and 5 write units, no auto-scaling).

The ``batch_write_item`` method only takes a max of 25 items at a time, so the script computes 25 items, writes them, then does it all over again.

After Dynamo has had enough, it will start throttling you and return any items that have not been written in the response. Once the script is
being throttled, it will start sleeping for 5 seconds until the failed items have been successfully written, after that it will exit.

.. literalinclude:: ../../../examples/dynamodb_batch_write.py
