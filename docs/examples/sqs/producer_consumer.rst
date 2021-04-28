
Here is a quick and simple producer/consumer example. The producer will put messages on the queue with a delay of up to 4 seconds between each put.
The consumer will read off any messages on the queue, waiting up to 2 seconds for messages to appear before returning.

Producer
+++++++++++++++++
.. literalinclude:: ../../../examples/sqs_queue_producer.py

Consumer
+++++++++++++++++
.. literalinclude:: ../../../examples/sqs_queue_consumer.py