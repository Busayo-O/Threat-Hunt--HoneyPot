# Install & populate MySQL

* Installed Microsoft visual c++ 2019 Redistribution Package(*64)-- This is My Sql Requirement

* MySQL was installed on the Virtual Machine with the Installation of the option “Developer Default” or “Full” so that Workbench/the GUI is installed.

  
<img width="1212" alt="image" src="https://i.imgur.com/MetZy6F.png"/>

* Started MySQL Workbench after the installation, created a new connection, and connected to MySQL
  
<img width="1212" alt="image" src="https://i.imgur.com/MetZy6F.png"/>


*Created data base with a 'dummy file" and downloaded the db_info_import_sgi unto the vm and imported it into the MySql by opening the SQL and executed it.

<img width="1212" alt="image" src="https://i.imgur.com/bOMnqwC.png"/>


*Results after running the query--results were selected from the credential table showing the usernames & passwords in the credential

<img width="1212" alt="image" src="https://i.imgur.com/s4CKCJc.png"/>

* Enabled MySQL audit / general query logging so every connection (success and failure) and query is written to a log file. This is done by running the query
  

  ```Kql 
  
** SET GLOBAL general_log = 'ON';

** SET GLOBAL log_output = 'FILE';

** SHOW VARIABLES LIKE 'general_log%';
```

* Logs are been generated and shown in the log files

<img width="1212" alt="image" src="https://i.imgur.com/2kUfXCz.png"/>


<img width="1212" alt="image" src="https://i.imgur.com/2kUfXCz.png"/>










