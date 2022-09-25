import angr
import angrutils
import bingraphvis
import monkeyhex

bin_addr = input("Enter the location of the binary to analyse: \n")

p = angr.Project(bin_addr, auto_load_libs = True)
cfg = p.analysis.CFGFast()
entry_node = cfg.get_any_node(p.entry)

node = entry_node

#while(len(node.succesors)!=0):
def new_node(node):
    if (len(node.successors)==0):
        return
    if (len(node.successors)==1):
        if(!node.is_syscall):
            for i in len(node.predessors):
                cfg.graph.remove_edge(u = node.predessors[i], v = node)
                cfg.graph.add_edge(u = node.predessors[i], v = node.succesors[0])
            cfg.graph.remove_edge(u = node, v = node.successors[0])
            cfg.remove_node(node)
    else:
        return

def check_each_node(node):
    new_node(node)
    for i in range(len(node.successors)):
        check_each_node(node.successors[i])
