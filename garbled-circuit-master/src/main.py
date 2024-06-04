#!/usr/bin/env python3
import logging
import ot
import util
import yao
from abc import ABC, abstractmethod

logging.basicConfig(format="[%(levelname)s] %(message)s",
                    level=logging.WARNING)


class YaoGarbler(ABC):
    """An abstract class for Yao garblers (e.g. Alice)."""
    def __init__(self, circuits):
        circuits = util.parse_json(circuits)
        self.name = circuits["name"]
        self.circuits = []

        for circuit in circuits["circuits"]:
            garbled_circuit = yao.GarbledCircuit(circuit)
            pbits = garbled_circuit.get_pbits()
            entry = {
                "circuit": circuit,
                "garbled_circuit": garbled_circuit,
                "garbled_tables": garbled_circuit.get_garbled_tables(),
                "keys": garbled_circuit.get_keys(),
                "pbits": pbits,
                "pbits_out": {w: pbits[w]
                              for w in circuit["out"]},
            }
            self.circuits.append(entry)

    @abstractmethod
    def start(self):
        pass


class Alice(YaoGarbler):
    """Alice is the creator of the Yao circuit.
	
	Alice reads the input file and then convert every binary integer to a n-bit binary integer
	
	Alice sends to Bob the number of values in it's input set: N
	Alice receives the number of values of Bob: M

    Alice creates a Yao circuit and sends it to the evaluator along with her
    encrypted inputs. Alice sends each of it's N inputs M times to Bob, in order to compare them.
	
	Alice receives the results of the shared computation, and then compute the common element set.

    Alice assumes that, once both Alice and Bob are aware of N and M, Bob will expect to receive the first value of Alice 
	M times, the second value M times, ..., the N-th value M times. Alice doesn't know the inputs of B.

    Attributes:
        circuits: the JSON file containing circuits, it will always be the circuit for n-bits compare
        oblivious_transfer: Optional; enable the Oblivious Transfer protocol
            (True by default).
    """
    def __init__(self, circuits, oblivious_transfer=True):
        super().__init__(circuits)
        self.socket = util.GarblerSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)

    def start(self):
        """Start Yao protocol."""
        #for circuit in self.circuits:
        #    to_send = {
        #        "circuit": circuit["circuit"],
        #        "garbled_tables": circuit["garbled_tables"],
        #        "pbits_out": circuit["pbits_out"],
        #    }
        #    logging.debug(f"Sending {circuit['circuit']['id']}")
        #    self.socket.send_wait(to_send)
        #    self.print(circuit)
        
        to_send = {
                "circuit": self.circuits[4]["circuit"],
                "garbled_tables": self.circuits[4]["garbled_tables"],
                "pbits_out": self.circuits[4]["pbits_out"],
            }
        self.socket.send_wait(to_send)
        self.print(self.circuits[4])

	
    def print(self, entry):
        """Alice is the creator and sender of the Yao circuit.
		
		Alice and Bob communicate with each other the cardinality of their sets: respectively N and M.
		Alice sends to Bob the circuit, and then Alice sends M times it's first input, M times it's second input,... 
		in order to compare all inputs of Alice to all inputs of Bob.
		
		Args:
            entry: A dict representing the circuit to evaluate.
		"""
		# Alice creates the circuit and gets relevant information to compute the result of the MPC
		
		# keys[port][bit], ex: keys[1][0] means that in the port 1 of the circuit, we put the value 0
		# pbits[port]^bit is used to allow Bob to decode the correct string. pbits[1] is random, ^ is the xor operation
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_keys = {  # map from Bob's wires to a pair (key, encr_bit)
            w: self._get_encr_bits(pbits[w], key0, key1)
            for w, (key0, key1) in keys.items() if w in b_wires
        }
		
		#Alice reads its inputs and then exchanges with Bob N,M
		
        #alice reads the input file
        alice_input_values_raw = util.read_input_file("input_alice.txt")
        #alice convert the input file into 4-bit values. Alice inputs are in the form: 1,5  =>  [[0,0,0,1] , [0,1,0,1]]
        alice_input_values_nbit = util.convert_input_list_to_nbit_list(alice_input_values_raw, 8)
        #N is the number of inputs of alice
        N = len(alice_input_values_raw)
        #Alice creates the sockets to exchange N,M with Bob
        number_of_inputs_Bob_to_Alice = util.Socket_connection_single_value(util.LOCAL_PORT_1)
        number_of_inputs_Alice_to_Bob = util.Socket_connection_single_value(util.LOCAL_PORT_2)
        #Alice sends to Bob the number of inputs of Alice: N
        number_of_inputs_Alice_to_Bob.send(N)
        #Alice receives from Bob the number of the inputs of Bob: M
        M = number_of_inputs_Bob_to_Alice.receive()
        print("N:" + str(N) + ", M:" + str(M))
		
        #compute the number of alice inputs
        N = len(alice_input_values_nbit)
        
		#Alice sends it's inputs to Bob using the strategy described above in the description of this function
		
        print(f"======== {circuit['id']} ========")
        shared_elements = []
        
        for i in range(N):
            print("\n")
            current_alice_input = alice_input_values_nbit[i]
			# given that Alice has to send the i-th input M times, she computes the i-th (key, encr_bit) only once
            for k in range(len(a_wires)):
                    a_inputs[a_wires[k]] = (keys[a_wires[k]][current_alice_input[k]], current_alice_input[k]^pbits[a_wires[k]])
			# Alice sends the i-th inputs M times.
			# Alice adds to the shared_elements list her i-th element iff the compare circuit responded at least onle with 1 (true)
            for j in range(M):
                result = self.ot.get_result(a_inputs, b_keys)
                str_result = ' '.join([str(result[w]) for w in outputs])
                if(str_result == "1"):
                    current_alice_input_integer = util.convert_bit_list_to_integer(current_alice_input)
                    util.add_to_list_if_not_already_present(current_alice_input_integer, shared_elements)
        print("The common elements between Alice and Bob are: " + str(shared_elements))
    
    def _get_encr_bits(self, pbit, key0, key1):
        return ((key0, 0 ^ pbit), (key1, 1 ^ pbit))


class Bob:
    """Bob is the receiver and evaluator of the Yao circuit.

    Bob receives the Yao circuit from Alice, computes the results and sends
    them back.

    Args:
        oblivious_transfer: Optional; enable the Oblivious Transfer protocol
            (True by default).
    """
    def __init__(self, oblivious_transfer=True):
        self.socket = util.EvaluatorSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)

    def listen(self):
        """Start listening for Alice messages."""
        logging.info("Start listening")
        
        
        try:
            for entry in self.socket.poll_socket():
                self.socket.send(True)
                self.send_evaluation(entry)
        except KeyboardInterrupt:
            logging.info("Stop listening")

    def send_evaluation(self, entry):
        """Bob and Alice communicate with each other the cardinality of their sets of numbers: respectively M and N, 
		then they use the compare circuit to confront each element of the set of A, with each element of the 
		set of B.
		Bob excect Alice to send her inputs in a certein way ()

        Args:
            entry: A dict representing the circuit to evaluate.
        """
        circuit, pbits_out = entry["circuit"], entry["pbits_out"]
        garbled_tables = entry["garbled_tables"]
        a_wires = circuit.get("alice", [])  # list of Alice's wires
        b_wires = circuit.get("bob", [])  # list of Bob's wires
		
		
		#Alice and Bob exchange N and M
		
        #Bob reads the input file
        bob_input_values_raw = util.read_input_file("input_bob.txt")
        #Bob convert the input file into n-bit values. the inputs are in the form: 1,5  =>  [[0,0,0,1] , [0,1,0,1]]
        bob_input_values_nbit = util.convert_input_list_to_nbit_list(bob_input_values_raw, 8)
        #M is the number of inputs of Bob
        M = len(bob_input_values_raw)
        #Bob creates the sockets to exchange N,M with Alice
        number_of_inputs_Bob_to_Alice = util.Socket_connection_single_value(util.LOCAL_PORT_1)
        number_of_inputs_Alice_to_Bob = util.Socket_connection_single_value(util.LOCAL_PORT_2)
        #N: an integer representing the number of Alice's inputs. N is sent from Alice to Bob.
        N = number_of_inputs_Alice_to_Bob.receive()
        #Bob sends M to Alice
        number_of_inputs_Bob_to_Alice.send(M)
        print("N:" + str(N) + ", M:" + str(M))
        
        print("Bob inputs: " + str(bob_input_values_nbit) + "\n")
		
		#compute the length of the circuit for Bob
        M = len(bob_input_values_nbit)
		
		#Bob expect Alice to send M times her first element, M times her second element, ..., M times her Nth (last) element
		#In this way we are able to compare each element of the set of A with each element in the set of B
		
        print(f"Received {circuit['id']}")
        shared_elements = []
        
        for i in range(N):
            for j in range(M):
                current_bob_input = bob_input_values_nbit[j]
				# create a dict in which it assigns at each input wire of Bob for the circuit, the input for Bob
				# Note that here the input is clear; it will be encrypted later, inside the ot.send_result function
                b_inputs_clear = {
                    b_wires[k]: current_bob_input[k]
                    for k in range(len(b_wires))
                }
                result_of_mpc = self.ot.send_result(circuit, garbled_tables, pbits_out,b_inputs_clear)
				# circuit["out"][0] is the output wire of the cmp circuit. Note that for any 
				# compare circuit, the output will always be singular. If you were to repurpose this 
				# code for functions with multiple outputs, you will have to change this
                str_result = result_of_mpc[circuit["out"][0]]
                if(str_result == 1):
                    current_bob_input_integer = util.convert_bit_list_to_integer(current_bob_input)
                    util.add_to_list_if_not_already_present(current_bob_input_integer, shared_elements)
					
        print("The common elements between Alice and Bob are: " + str(shared_elements))


class LocalTest(YaoGarbler):
    """A class for local tests.

    Print a circuit evaluation or garbled tables.

    Args:
        circuits: the JSON file containing circuits
        print_mode: Print a clear version of the garbled tables or
            the circuit evaluation (the default).
    """
    def __init__(self, circuits, print_mode="circuit"):
        super().__init__(circuits)
        self._print_mode = print_mode
        self.modes = {
            "circuit": self._print_evaluation,
            "table": self._print_tables,
        }
        logging.info(f"Print mode: {print_mode}")

    def start(self):
        """Start local Yao protocol."""
        for circuit in self.circuits:
            self.modes[self.print_mode](circuit)

    def _print_tables(self, entry):
        """Print garbled tables."""
        entry["garbled_circuit"].print_garbled_tables()

    def _print_evaluation(self, entry):
        """Print circuit evaluation."""
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        garbled_tables = entry["garbled_tables"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_inputs = {}  # map from Bob's wires to (key, encr_bit) inputs
        pbits_out = {w: pbits[w] for w in outputs}  # p-bits of outputs
        N = len(a_wires) + len(b_wires)

        print(f"======== {circuit['id']} ========")

        # Generate all possible inputs for both Alice and Bob
        for bits in [format(n, 'b').zfill(N) for n in range(2**N)]:
            bits_a = [int(b) for b in bits[:len(a_wires)]]  # Alice's inputs
            bits_b = [int(b) for b in bits[N - len(b_wires):]]  # Bob's inputs

            # Map Alice's wires to (key, encr_bit)
            for i in range(len(a_wires)):
                a_inputs[a_wires[i]] = (keys[a_wires[i]][bits_a[i]],
                                        pbits[a_wires[i]] ^ bits_a[i])

            # Map Bob's wires to (key, encr_bit)
            for i in range(len(b_wires)):
                b_inputs[b_wires[i]] = (keys[b_wires[i]][bits_b[i]],
                                        pbits[b_wires[i]] ^ bits_b[i])

            result = yao.evaluate(circuit, garbled_tables, pbits_out, a_inputs,
                                  b_inputs)

            # Format output
            str_bits_a = ' '.join(bits[:len(a_wires)])
            str_bits_b = ' '.join(bits[len(a_wires):])
            str_result = ' '.join([str(result[w]) for w in outputs])

            print(f"  Alice{a_wires} = {str_bits_a} "
                  f"Bob{b_wires} = {str_bits_b}  "
                  f"Outputs{outputs} = {str_result}")

        print()

    @property
    def print_mode(self):
        return self._print_mode

    @print_mode.setter
    def print_mode(self, print_mode):
        if print_mode not in self.modes:
            logging.error(f"Unknown print mode '{print_mode}', "
                          f"must be in {list(self.modes.keys())}")
            return
        self._print_mode = print_mode


def main(
    party,
    circuit_path="circuits/default.json",
    oblivious_transfer=True,
    print_mode="circuit",
    loglevel=logging.WARNING,
):
    logging.getLogger().setLevel(loglevel)

    if party == "alice":
        alice = Alice(circuit_path, oblivious_transfer=oblivious_transfer)
        alice.start()
    elif party == "bob":
        bob = Bob(oblivious_transfer=oblivious_transfer)
        bob.listen()
    elif party == "local":
        local = LocalTest(circuit_path, print_mode=print_mode)
        local.start()
    else:
        logging.error(f"Unknown party '{party}'")


if __name__ == '__main__':
    import argparse

    def init():
        loglevels = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL
        }

        parser = argparse.ArgumentParser(description="Run Yao protocol.")
        parser.add_argument("party",
                            choices=["alice", "bob", "local"],
                            help="the yao party to run")
        parser.add_argument(
            "-c",
            "--circuit",
            metavar="circuit.json",
            default="circuits/default.json",
            help=("the JSON circuit file for alice and local tests"),
        )
        parser.add_argument("--no-oblivious-transfer",
                            action="store_true",
                            help="disable oblivious transfer")
        parser.add_argument(
            "-m",
            metavar="mode",
            choices=["circuit", "table"],
            default="circuit",
            help="the print mode for local tests (default 'circuit')")
        parser.add_argument("-l",
                            "--loglevel",
                            metavar="level",
                            choices=loglevels.keys(),
                            default="warning",
                            help="the log level (default 'warning')")

        main(
            party=parser.parse_args().party,
            circuit_path=parser.parse_args().circuit,
            oblivious_transfer=not parser.parse_args().no_oblivious_transfer,
            print_mode=parser.parse_args().m,
            loglevel=loglevels[parser.parse_args().loglevel],
        )

    init()
