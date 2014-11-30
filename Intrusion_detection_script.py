import psutil as ps
from psutil import *
import os
import os.path
import time
from math import sqrt
import subprocess as sp


def create_logfile(logPath='/Program Files'):
    if not os.path.exists(logPath):
        os.mkdir(logPath)
    punctuator='-'*90 + '\n'
    format1='%s  %s %s %s %s %s'
    #   print ('Press q to quit the logging session. Any other key to continue.')
    inp=''
    c=0
    while inp!='q':
        proc=ps.get_process_list()
        print (proc)
        # proc=sorted(proc, key=lambda proc: proc.name)
        c+=1
        log_file_name=logPath + '/' + 'log_file.log' + str(c) #% int(time.time())
        f=open(log_file_name, 'a')
        f.write(punctuator)
        f.write(time.ctime() + "\n")
        f.write(format1 % ("NAME",  "RSS", "VMS", "%CPU", "%MEM", "%NET"))
        f.write("\n")

        for p in proc:
            name=p.name
          #  path=p.path
            rss, vms=p.get_memory_info()
            rss=str(rss)
            vms=str(vms)
            cpu_usage=p.get_cpu_percent()
            mem_usage=p.get_memory_percent()
            connections=p.connections()
            f.write(format1 % (name, rss, vms, cpu_usage, mem_usage, connections))
            f.write("\n")
        f.close()
        print ('Done with logging.')
        time.sleep(5)
        #inp=input()
        #if (inp!='q'):
        #    print ('Logging...')

def mean_std(lis):
    sum_of_nos=sum(lis)
    n=len(lis)
    mean=sum_of_nos/n
    sum_of_squares=sum([(i-mean)**2 for i in lis])
    var=sum_of_squares/(n-1)
    print (var)
    return mean, sqrt(var)

    
    
    

def average(pid):
    cpu_usage=[]
    mem_usage=[]
    rss_acc=[]
    vms_acc=[]
    for i in range(10000):
        proc=ps.get_process_list()
        # print (proc)
        proc_pids=ps.get_pid_list()
        proc_pids=sorted(proc_pids)
        proc_dic={}
        for i in range(len(proc_pids)):
            proc_dic[proc_pids[i]]=proc[i]
        current_proc=proc_dic[pid]
      
        rss, vms=current_proc.get_memory_info()
        p=current_proc
        rss_acc.append(float(rss))
        vms_acc.append(float(vms))
        cpu_usage.append(p.get_cpu_percent())
        # print (cpu_usage, type(cpu_usage))
        mem_usage.append(p.get_memory_percent())
    return mean_std(rss_acc), mean_std(vms_acc), mean_std(cpu_usage), mean_std(mem_usage)

def get_dll_count(pid, path_to_command="C:/Listdlls.exe"):
    s=str(sp.check_output("C:/Listdlls.exe "+str(pid)))
    lis=s.split('\r')
    count=0
    for i in lis:
        if '.dll' in i:
            count+=1
    return count, path_to_command

def get_hamming_distance(before_attack, after_attack):
    acc=0
    for ch1, ch2 in zip(before_attack, after_attack):
        if ch1!=ch2:
            acc+=1
    return acc
    
    

    
        
def flag_attack_for_proc(pid):
    proc=ps.get_process_list()
    proc_pids=ps.get_pid_list()
    proc_pids=sorted(proc_pids)
    print("Pre-computing...")
    ret=average(pid)
    print("Done.")
    rss_tuple=ret[0]
    vms_tuple=ret[1]
    cpu_tuple=ret[2]
    mem_tuple=ret[3]
    
    mean_rss=rss_tuple[0]
    std_rss=rss_tuple[1]
    beg_rss=mean_rss-std_rss
    end_rss=mean_rss+std_rss

    mean_vms=vms_tuple[0]
    std_vms=vms_tuple[1]
    beg_vms=mean_vms-std_vms
    end_vms=mean_vms+std_vms
    
    mean_cpu=cpu_tuple[0]
    std_cpu=cpu_tuple[1]
    beg_cpu=mean_cpu-std_cpu
    end_cpu=mean_rss+std_cpu
    
    mean_mem=mem_tuple[0]
    std_mem=mem_tuple[1]
    beg_mem=mean_mem-std_mem
    end_mem=mean_mem+std_mem

    dll_count=get_dll_count(pid)[0]
    str1=sp.check_output(get_dll_count(pid)[1] + " " + str(pid))
    
    try:
        while pid in proc_pids and (len(proc)==len(proc_pids)):
            proc=ps.get_process_list()
            #print (proc)
            proc_pids=ps.get_pid_list()
            proc_pids=sorted(proc_pids)
            proc_dic={}
            for i in range(len(proc_pids)):
                proc_dic[proc_pids[i]]=proc[i]
            # print (proc_dic)
            current_proc=proc_dic[pid]
            if (current_proc.name() is not None):
                print ("Process being analysed is ", current_proc.name())
            rss, vms=current_proc.get_memory_info()
            p=current_proc
            

            print ("---FIRST TIME---") 
            count1=get_dll_count(pid)[0]
            rss=float(rss)
            if rss < beg_rss or rss > end_rss:
                print("RSS anomaly detected")
            print ("RSS", rss)
            vms=float(vms)
            if vms < beg_vms or vms > end_vms:
                print("VMS anomaly detected")
            print ("VMS", vms)
            cpu_usage=p.get_cpu_percent(interval=1)
            if cpu_usage < beg_cpu or cpu_usage > end_cpu:
                print("CPU anomaly detected")
            print (cpu_usage, type(cpu_usage))
            mem_usage=p.get_memory_percent()
            if mem_usage < beg_mem or mem_usage > end_mem:
                print("Memory anomaly detected")
            print (mem_usage, type(mem_usage))
            connections=p.connections()
            print ("Network", connections)
            time.sleep(2)
            print ("---SECOND TIME---")
            str2=sp.check_output(get_dll_count(pid)[1] +" "+ str(pid))
            rss1, vms1=current_proc.get_memory_info()
            rss1=float(rss)
            print ("RSS", rss1)
            vms1=float(vms1)
            print ("VMS", vms1)
            cpu_usage1=p.get_cpu_percent()
            print (cpu_usage1)
            mem_usage1=p.get_memory_percent()
            print (mem_usage1)
            connections1=p.connections()
            print ("Network", connections)
            dist=get_hamming_distance(str1, str2)
            count2=get_dll_count(pid)[0]
            if (count2 > count1 or count2 < count1 or dll_count < count1 or dll_count < count2):
                print ("Difference in number of DLL files detected")
            if (dist > 10):
                print ("DLL anomaly detected.")
            if (rss !=0):
                rss_ratio=rss1/rss
            else:
                rss_ratio=float('inf')
                print ("Anomaly detected! RSS ratio cannot be infinity")
            if (vms != 0):
                vms_ratio=vms1/vms
            else:
                vms_ratio=float('inf')
                print ('Anomaly detected! VMS ratio cannot be infinity')
            if (cpu_usage != 0):
                cpu_ratio=cpu_usage1/cpu_usage
                if (cpu_ratio > 2 or cpu_ratio < 0.6):
                    print ("Warning! Abnormalities in CPU usage detected.")
            else:
                print ("Warning! CPU usage is indeterminate. Beware!")
                print ("The offending process is ", p.name(), " with PID ", pid)
            
            if (mem_usage != 0):
                mem_ratio=mem_usage1/mem_usage
                if (mem_ratio > 2 or mem_ratio < 0.5):
                    print ("Warning! Abnormalities in memory usage detected.")
            else:
                print ("Warning! Memory usage is infinity. Beware!")
                print ("The offending process is ", p.name(), " with PID ", pid)
            if (connections is None and connections1 is not None):
                print ('Warning! ', p.name(), ' is trying to connect to the Internet. Are you sure you want to allow this?')
                x=input()
                if (x!='y' and x!='Y' and x!='Yes' and x!='yes' and x!='YES'):
                    p.terminate()
    except NameError:
        print ("Name error")
        pass
    except ProcessLookupError:
        print ("Process lookup error")
        pass
    except ps.NoSuchProcess:
        print ("Process terminated.")
        pass
  

##    # Network traffic
##    # Memory consumed by a given process
##    # DLL and registry objects that are being used
##    # CPU Usage
##    # I need to get all this in the normal state
##    # Not necessarily in that order
##    print ("\n\n---MEMORY STATISTICS---\n")
##    print ("Virtual")
##    print (psutil.virtual_memory())
##    print ("\nSwap\n")
##    print (psutil.swap_memory())
##    print ("\n\n---NETWORK TRAFFIC---\n")
##    dic_net=psutil.net_io_counters(pernic=True)
##    for key in dic_net:
##        print (key, ": ", dic_net[key])
##        print ("TYPE= ", type(dic_net[key]))
##    lis_net=psutil.net_connections()
##    for i in lis_net:
##        print (i)
##    print ("\n\n")
##    # After all this, we finally get to the individual process management
##    proc_ids=get_running_procs()[0]
##    proc_names=get_running_procs()[1]
##    # Now I have the ids and the names of the processes that are running
##    proc_lis=[]
##    for proc in psutil.process_iter():
##        try:
##            pinfo=proc.as_dict(attrs=['pid', # Process ID
##                                      'name', # Name of the process (if any)
##                                      'status', # status of the process (whether or not it is running)
##                                      'username', # owner of the process
##                                      'io_counters', # Number of read write operations and the amount of bytes read or written
##                                      'num_threads', # Number of threads used by the process
##                                      'cpu_percent', # Percentage of cpu utilization of the process
##                                      'memory_info', # Returns a tuple representing the Resident Set Size and Virtual Memory Size
##                                      'memory_percent', # Percentage of memory utilization
##                                      'connections']) # Network 
##        except psutil.NoSuchProcess:
##            pass
##        else:
##            proc_lis.append(pinfo)
##            print (pinfo)
##    print (proc_lis)
#def get_attacked_parameters():
    # Do the same thing that the previous function is doing
    # but run it every one second in order to see the changes
    # Once a deviation is too much, flag an attack
