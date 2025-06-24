================================

ACME Bank Web Application Secure

================================

IMPORTANT

1// 
To run the code, you may need to run 'create_db_hased.py'. This will create a database instance and store all passwords as a hash.

2//
To run without AWS credentials or Secrets Manager, in 'config.py':

    - Comment lines 33-41
    - Uncomment lines 44-47

In my secure version credentials are not hard-coded in plain-text - this is
a quick addition to make my application quickly testable :) 