# Install & populate MySQL
Installed and configured MySQL on Windows Virtual Machine, created a sample corporate database imported sample data, and enabled MySQL general query logging and prepared the database logs for security Monitoring. The logs generated during this phased, was used in Phase 3 for log collection and monitoring.

# Steps

A) Installed Microsoft visual c++ 2019 Redistribution Package(*64) on the windows Virtual Machine-- This is a requirement for the MySQL.

B) Installed MySQL Server and Workbench
  
  * Downloaded and launched MySQL Installer.
  
  * Selected the "Developer Default" of "Full Installation".
  
  * Followed the installation process using the default settings.
  
  * Created a strong password for the MySQL root account.
  
  
<img width="1212" alt="image" src="https://i.imgur.com/MetZy6F.png"/> MySQL Server and MySQL Workbench are successfully installed.

C) Established a MySQL Connection

  * Launched MySQL Workbench.

  * Created a new connection.

  * Configured the connection.

  * Tested the connection.

  * Connected to the MySQL server.

  
  
<img width="1212" alt="image" src="https://i.imgur.com/MetZy6F.png"/> MySQL Workbench successfully connected to the databaseserver.


D) Imported Dummy Corporate Data

* Downloaded the file db_info_import.sql file

* In the MySQL Workbench, located the db_info)import.sql file downloaded

* Executed the SQL Script for completion.


<img width="1212" alt="image" src="https://i.imgur.com/bOMnqwC.png"/> *Created data base with a 'dummy file" and downloaded the db_info_import_sgi unto the vm and imported it into the MySql by opening the SQL and executed it.


E) Verified Database Creation

* Navigated to the Schemas panel in MySQL Workbench.

* Refreshed the Schemas list and confirmed that the database name appeared.

*Results after running the query--results were selected from the credential table showing the usernames & passwords in the credential

<img width="1212" alt="image" src="https://i.imgur.com/s4CKCJc.png"/>




F) Enabled MySQL general query logging 

This is to capture database queries and connection activity for security monitoring.  These commands enabled general querry logging,  directed the output to a file and displayed the current logging configuration. 
  
Executed the following SQL commands in MySQL Workbench:

  
  ---Enabled MySQL general query logging
** SET GLOBAL general_log = 'ON';

 ---Write log output to a file
** SET GLOBAL log_output = 'FILE';

---Verify logging settings
** SHOW VARIABLES LIKE 'general_log%';
```


<img width="1212" alt="image" src="https://i.imgur.com/2kUfXCz.png"/> - * Logs are been generated and shown in the log files


G) Configured the MySQL Configuration File

* Downloaded the file my.ini configuration file and program path indicated- C:\ProgramData\MySQL Server 8.0\my.ini and the expected log file location is C:\ProgramData\MySQL Server 8.0\Data\mysql_general.log.

The actual path was verified using MySQL configuration variables.



H) Generated Test Database Activity

- Opened the MySQL Workbench and executed test queries. These query generated database activity that is used to verify logging.


SELECT NOW();

SHOW DATABASES;

SHOW TABLES FROM ihp_corp:


<img width="1212" alt="image" src="https://i.imgur.com/2kUfXCz.png"/>


I) Verified MySQL General Logs
   Execute:

SHOW VARIABLES LIKE 'general_logs';

SHOW VARIABLES LIKE 'log_output';

SHOW VARIABLES LIKE 'general_log_file';

* Navigated to the general query log

* Confirmation that SQL queries has been recorded.




