The intrusion_detection_script.py is the python script that uses psutils in order to monitor the processes that are running on the system. It has a variety of function that perform various tasks documented as follows:

create_logfile()

Parameters:
	Path directory to the folder where the log file is supposed to be stored.

Task:
	This function periodically logs the system state into a log file, whose path is passed to the function as an argument.

mean_std():

Parameters:
	A list of floating point numbers

Task:
	This function calculates the mean and the standard deviation of the list that is passed as parameter and returns those values

average()

Parameters:
	PID of a process

Task:
	Calculates and returns the mean and standard deviation of the following using the mean_std() function:
	1. RSS
	2. VMS
	3. CPU usage
	4. Memory usage

flag_attack_for_proc(pid):

Parameters:
	PID of a suspicious process.

Task:
	Flashes a warning if the process under consideration is suspected to be under an attack. This is measured using the following parameters:
	1. RSS
	2. VMS
	3. Patterns of CPU usage
	4. Patterns of memory usage
	If any of the above stated parameters deviates from the standard behaviour (i.e. displays values which are out of this range [mean - standard deviation, mean + standard deviation]), a warning is flashed on the console. The script runs as long as the process under suspicion is running.


get_hamming_distance()

Parameters:
	Two strings

Task:
	This function returns the Hamming distance between two strings. It is then used to analyse the difference in DLL usage when the system is under attack and when the system is normal.

It periodically logs the output into logfiles using the dumps taken from psutils. It measures memory usage, network connections and CPU usage as parameters.
