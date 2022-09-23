import angr
import sys

#TODO
#############Just writing basic code line##############
############Include them in proper functions##############

bin_addr = input("Input the address of binary for generation of control flow graph\n ")

# make the angr Project of the issued binary
p = andr.Project(bin_addr, auto_load_libs = True)

#create an entry state of the program.
state = p.factory.entry_state()

#Now create a simulation_manager
sm = p.factory.simulation_manager(state)

#Put a condition on program to stop once it ncounter a syscall

sm.run(until=lambda sm )

:
