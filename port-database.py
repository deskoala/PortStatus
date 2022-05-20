import nmap #First we import the libraries
import csv
from datetime import datetime
import pandas as pd
import sqlite3
import time
import schedule #It is necessary to run pip install schedule to get this module
import os


def port_scan(): #I made this code to be scheduled to run/refresh every second, you can view the database update by refreshing in the DB Browser for SQLite.   
    scanner = nmap.PortScanner() #We start with creating the scanner object itself

    list = [7, 20, 21, 22, 23, 25, 53, 69, 80, 88, 102, 110, 135, 137, 139, 143, 381, 383, 443, 464, 465, 587, 593, 636, 691, 902, 989, 990, 993, 995, 
    1025, 1194, 1337, 1589, 1725, 2082, 2083, 2483, 2484, 2967, 3074, 3306, 3724, 4664, 5432, 5900, 6665, 6999, 6970, 8086, 8087, 8222, 9100, 10000, 12345,
    27374, 18006]
    length = len(list)
    target = '127.0.0.1' #This is our local host ip to be scanned

    f = open('porthistory.csv', 'a', newline = '') #Creates a csv if it does not already exist, the 'a' is for appending if the csv already exists. The newline removes spaces inbetween lines.
    header = ['port', 'state', 'time']
    writer = csv.writer(f)
    writer.writerow(header)

    def startScan(l, len, t):
        """ This function is what we use to scan our ip's ports
            The for loop goes through the beginning port to the end port incremented by 1
            At the end of the loop we have all out ports and their state of being either open or close printed
        """
        for i in range(len):
            curport = (l[i])
            result = scanner.scan(t, str(curport)) #We want the iterator in the form of a string so we wrap it in a str() method
            result = result['scan'][t]['tcp'][curport]['state'] #This overwrites the result in a readable form to just include the 'open' or 'close' state
            print(f'Port {curport} is {result}.') #The f-string subsitites what is inside the {} for variable values that exist.
        
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            data = [curport, result, dt_string] #Puts the scan results and state into data along with the exact time accessed.
            writer.writerow(data) #Writes the data into the csv file.
        

    startScan(list, length, target)
    f.close() #Closes the writing to the csv file.

    df = pd.read_csv('porthistory.csv') #Creating a data frame using pandas
    print(df)

    connection = sqlite3.connect('porthisdb.db') #Creates or connects to already existing sqlite database.
    df.to_sql('port_state_history', connection, if_exists='replace', index=False) #This adds the dataframe created with pandas to the database

    connection.commit()
    connection.close()

schedule.every(5).seconds.do(port_scan) #This enables the program to constantly update the history of the port states every second to the port_state_history sqlite database
while True:
    schedule.run_pending()
    time.sleep(1)

#Ctrl + C stops the program from running