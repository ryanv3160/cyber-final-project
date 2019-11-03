from datetime import datetime

def detect(channel):
    
    while True:
        table = channel.get()
        # TODO: perform detect logic
        channel.put(table)



