# traffic-classifier
First Python project. I started learning to program with Python when I started this project.Since every traffic right now is encrypted,
I tried to make a script, that can count statistical parameters for ML algorithm and use them for traffic type. Still in progress. 
Some of problems I'm facing right now:
1. Im using Scapy for traffic analyzing. Scapy counts sessions in a weird way. It doubles the sessions and some of my parameters becomes 0(SOLVED)
2. Traffic captured in windows has a lot of "sound" in it, so it might change classifier results.
