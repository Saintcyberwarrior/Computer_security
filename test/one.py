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

#Put a condition on program to stop once it encounter a syscall
#sm.run(until=lambda sm: sm.is_simprocedure==True)

#condition to check if there is any branching

#TODO
#there might be braches while traversing the graph in reverse direction, need to take care of that case as well.
sm.run(until=lambda sm_:len(sm_.active)>1)

def syscall_func(state):
	print('the syscall made now was', state.inspect.syscall_name)

def call_func(state):
	print('the address of function called is: ', state.inspect.function_address)

def ret_func(state):
	print('Wohoo, we just returned')

def exit_func(state):
	print('the exit target is', state.inspect.exit_target, 'and the exit guard is', state.inspect.exit_guard, 'and the jumpkind is', state.inspect.exit_jumpkind)

##I have no idea what guard is#
state.inspect.b('syscall', when=angr.BP_BEFORE, action = syscall_func)# here we can add condition function also
state.inspect.b('call', when=angr.BP_BEFORE, action = call_func)
state.inspect.b('return', when=angr.BP_BEFORE, action = ret_func)
state.inspect.b('exit', when=angr.BP_BEFORE, action = exit_func)

##############################So, so this way we can isolate the states of our interest############

##Now, put them in a loop###
