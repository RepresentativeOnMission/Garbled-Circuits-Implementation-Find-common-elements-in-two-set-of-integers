# Garbled Circuits

This work implements garbled circuits to solve the following problem: Given two parties, A and B, let A have a set of 8 bit integers $a_1, \dots, a_n$, and B have a set of 8 bit integers $b_1, \dots, b_n$, then the objective is to find the set of common elements shared betweem A and B, without neither A nor B knowing the set of items belonging to the other user, nor making use of any central authority.

This project makes use of cryptographic tools known as "Garbled Circuit", and it is based on the repository "https://github.com/ojroques/garbled-circuit/tree/master", which I adapt to my specific task.

![alt text](https://github.com/RepresentativeOnMission/Garbled-Circuits-Implementation-Find-common-elements-in-two-set-of-integers/blob/main/Paper/images/8bit_circuit.PNG/?raw=true)


## How to use?
* check that you have the required libraries to run the code, you will find the libraries in "./Paper/How to use.pdf"
* go to "./garbled_circuit_master/src/"
* insert the inputs of both Alice and Bob, in the format shown in "./Paper/How to use.pdf"
* run Bob by executing "python main.py bob"
* run Alice executing "python main.py alice -c circuits/emp.json"
* the results will be shown in both Alice and Bob windows

## Is it possible to compare numbers that requires more than 8 bits
Yes, and it is quite easy to extend this algorithm to compare n-bits integers just following the instructions shown in "./Paper/How to use.pdf".

## It is possible to adapt the code to other tasks
You can create your own circuits, and implement custom tasks by following the steps shown in both "./Paper/How to use.pdf", and "https://github.com/ojroques/garbled-circuit/tree/master".
