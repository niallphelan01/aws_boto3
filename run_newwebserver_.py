#!/usr/bin/env python3
import logging  # Logging functionality
import boto3  # import the boto api
import subprocess
import time  # pausing the interface
import s3_check_create  # seperate python file to check for s3 bucket
import sys  # this allows you to use the sys.exit command to quit/logout of the application
from datetime import datetime, timedelta
# Menu for new webserver

# Global declaration of ec2 and cloudwatch
cloudwatch = boto3.resource('cloudwatch')
ec2 = boto3.resource('ec2')
filename='log/aws_assignment.log'
# Configuration for the logfile https://docs.python.org/3/howto/logging.html + https://www.pylenin.com/blogs/python-logging-guide/
logger_format= "%(asctime)s::%(levelname)s::%(name)s::"\
             "%(filename)s::%(lineno)d::%(message)s"
logging.basicConfig(
    filename= filename,
    level=logging.DEBUG,
    format = logger_format,
    datefmt='%d/%m/%Y %I:%M:%S %p'
)

def main():    #Main function to call the main menu
    logging.info('Program started')
    menu()
def menu():
    logging.info('Main menu selected')
    print("\n\n\n              ************MAIN MENU**************")
    time.sleep(0.02)
    print()

    choice = input("""
                      A: Instance Menu
                      B: Monitoring menu
                      C: Open Logfile (to be completed)
                      -------------------
                      Q: Quit/Log Out

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        instance_menu()
    elif choice == "B" or choice == "b":
        monitor_menu()
    elif choice == "C" or choice == "c":
        open_logfile()
    elif choice == "Q" or choice == "q":
        logging.info("Exiting of program")
        sys.exit()
    else:
        print("You must only select either A,B,C, or D.")
        print("Please try again")
        menu()
def instance_menu():
    logging.info('Instance Menu Selected')
    print("\n\n\n              ************INSTANCE MENU**************")
    time.sleep(0.02)
    print()

    choice = input("""
                      A: Create a new instance
                      B: List all instances (any state)
                      C: Connect to running instance "and" setup webserver
                    -----------------------------------------------
                      D: Terminate instance
                    -----------------------------------------------
                      Q: Back to Main Menu

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        logging.info('Create new instance selected')
        createNewInstance()
    elif choice == "B" or choice == "b":
        list_all_instance()   #list all instances - different function to show all statuses
    elif choice == "C" or choice == "c":
        connectToInstance()   #list all running instances and then select one to excute further scripts on
    elif choice == "D" or choice == "d":
        quitInstance()
    elif choice == "Q" or choice == "q":
        menu()
    else:
        print("You must only select either A,B,C, or D.")
        print("Please try again")
        instance_menu()
def monitor_menu():
    print("\n\n\n              ************MONITORING MENU**************")
    time.sleep(0.02)
    print()

    choice = input("""
                      A: Monitor the CPU utilisation on an instance
                      B: Set Alarm on instance (note less than 20%)
                      ------------------------
                      C: Set custom monitoring on EC2 instance to cloudwatch
                      ------------------------ 
                      Q: Back to Main Menu

                      Please enter your choice: """)

    if choice == "A" or choice == "a":
        select_monitor()
    elif choice == "B" or choice == "b":
        cloudwatch_alarm()
    elif choice == "C" or choice == "c":
        pushmonitoring()
    elif choice == "Q" or choice == "q":
        menu()
    else:
        print("You must only select either A,B,C, or D.")
        print("Please try again")
        monitor_menu()
def createNewInstance():
    ec2 = boto3.resource('ec2')
    print("\nStarting instance creation process, please be patient")
    choiceInstanceType = input("""
                              What instance type would you like?
                              A: t2.micro
                              B: t2.nano(default)
                              If A "or" B "not" choosen then default "is" selected""")
    if choiceInstanceType == "A" or choiceInstanceType == "a":
        choosenInstanceType = "t2.micro"
    else:
        choosenInstanceType = "t2.nano"
    try:
        instance = ec2.create_instances(
            ImageId='ami-099a8245f5daa82bf',  # Default instance
            MinCount=1,
            MaxCount=1,
            InstanceType=choosenInstanceType,  # t2 nano default or micro depending upon selection
            KeyName='kp 2020',
            SecurityGroupIds=['sg-0e17eda475266e679'],  # one of my security groups that has http and ssh
        )
        print("Instance ID:" + instance[0].id + " being created. Please be patient!")
    except:
        logging.error("Couldn't create an instance")
        print("Couldn't create an instance")
        input("\nPress Enter to continue...")
        instance_menu()
    # instance created but no tags inserted.
    try:
        instance[0].wait_until_running()
        print("Instance running")
    except:
        print("Cannot check for instanance running")
        logging.warning("Unable to check for instance running")
    # wait until the instance is running
    try:
        choiceTag = input("""Would you like to add a Tag? Y/N: """)
        if choiceTag == "Y" or choiceTag == "y":
            choiceTagKey = input("""Please enter a key name: """)
            choiceTagValue = input("""Please enter a tag value: """)
            print(choiceTagKey + choiceTagValue)
            try:
                print(
                    ec2.create_tags(Resources=[instance[0].id], Tags=[{'Key': choiceTagKey, 'Value': choiceTagValue}]))
                logging.info(
                    "Instance " + instance[0].id + " created with Tag key " + choiceTagKey + " value " + choiceTagValue)
            except:
                print("Couldn't add a tag")
        else:
            print("No tag created")
            logging.info("no tag added")
    except:
        logging.warning("Couldn't add a tag to a instance")
        print("Cannot add tags to uncreated instance")
    # tag now added to the instance
    try:
        print("Instance running: " + instance[0].id)
    except:
        logging.warning("No instance running on the system due to errors")
        print("No instance running")
    input("\nPress Enter to continue...")
    instance_menu()
def list_all_instance():  # Listing of all instances in all statuses
    ec2 = boto3.resource('ec2')
    print("\nAttempting to list instances, please be patient")
    try:
        instance_list = []
        for instance in ec2.instances.all():
            print(instance.id, instance.state, instance.public_ip_address)
            instance_list.append(instance)
        logging.warning("Instance list created without issue")
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error handling instances more than likely due to connection")
    input("\nPress Enter to continue...")
    instance_menu()
def connectToInstance():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")

    if not instance_list:
        logging.warning("No running instances")
        print("No running instances")
        input("\nPress Enter to continue...")
        instance_menu()
    else:
        choice = input("""Which instance would you like to setup a server on?""")
        print(choice)
        try:
            ssh_text = "ssh -o StrictHostkeyChecking=no -i kp2020.pem ec2-user@"
            selected_instance = instance_list[
                int(choice)]  # convert string input to int and select the value in the array
            print(selected_instance)
            subprocess.run(
                ssh_text + selected_instance.public_ip_address + " \ 'sudo yum -y install httpd; sudo systemctl enable httpd; sudo service httpd start;'",
                shell=True)
            # subprocess.run("ssh -o StrictHostkeyChecking=no -i kp2020.pem ec2-user@" + selectedInstance.public_ip_address +" \ 'sudo systemctl enable hqttpd'", shell=True)
            # subprocess.run("ssh -o StrictHostkeyChecking=no -i kp2020.pem ec2-user@" + selectedInstance.public_ip_address +" \ 'sudo service httpd start'", shell=True)
            s3_check_create.check_bucket("witdemo-23-01-2020")  # check to see if the required s3 bucket is created
            subprocess.call('curl "http://devops.witdemo.net/image.jpg" -o "image.jpg"', shell=True)
            # upload the image to s3 bucket
            s3 = boto3.resource("s3")
            bucket_name = "witdemo-23-01-2020"
            object_name = "image.jpg"
            try:
                response = s3.Object(bucket_name, object_name).upload_file(object_name, ExtraArgs={
                    'ACL': 'public-read'})  # upload the object to the s3bucket specified
                print(
                    response)  # if the upload is successful then we will use this as the image upload for the webserver
                html10 = "echo \<img src=https://s3-eu-west-1.amazonaws.com/" + bucket_name + "/" + object_name + "\> >> index.html'"
                copy_text = " \ 'sudo cp index.html /var/www/html/index.html'"  # only copy the index.html file to the webserver location
            except Exception as error:
                print(error)
                try:  # if the aws upload doesnt work then I am going to send a local copy to the webserver via scp
                    subprocess.run("'scp -i kp2020.pem image.jpg ec2-user@" + selected_instance.public_ip_address + ":'",
                                   shell=True)  # scp to copy the image file to the webserver
                    copy_text = " \ 'sudo cp index.html image.jpg /var/www/html/'"  # copy both the index.html and the image.jpg as the upload/download from s3 bucket with fail
                    html10 = "echo \<img src=/image.jpg\> >> index.html'"  # copy the image from the local source on the webserver sent over by scp
                except:
                    print("didn't work update text")

            # buildup the web page on the apache server
            # addiitonal informaiton on the  instance meta data retrival https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
            html1 = " \ 'echo \<html\> \<body\> > index.html;"
            html2 = "echo \<h1\>Instance Information\</h1\> >>index.html;"
            html3 = "echo \<h2\> Private IP address \</h2\> >> index.html;"
            html4 = "curl http://169.254.169.254/latest/meta-data/local-ipv4 >>index.html;"
            html5 = "echo \<h2\> Availability zone \</h2\> >> index.html;"
            html6 = "curl http://169.254.169.254/latest/meta-data/placement/availability-zone >>index.html;"
            html7 = "echo \<h2\> Security Groups \</h2\> >> index.html;"
            html8 = "curl http://169.254.169.254/latest/meta-data/security-groups >>index.html;"
            html9 = "echo \<br\>Here is the image:\<br\> >>index.html;"
            html_total = html1 + html2 + html3 + html4 + html5 + html6 + html7 + html8 + html9 + html10
            subprocess.run(ssh_text + selected_instance.public_ip_address + html_total, shell=True)
            subprocess.run(ssh_text + selected_instance.public_ip_address + copy_text, shell=True)
            subprocess.call('firefox ' + selected_instance.public_ip_address, shell=True)

            instance_menu()
        except:
            logging.warning("Issue with choice entry to select an instance")
            print("Incorrect choice, as server may not be fully loaded,  please try again")
            input("\nPress Enter to continue...")
            instance_menu()
def instance_listing(status):
    i = 0
    instance_list = []
    filters = [
        {
            'Name': 'instance-state-name',
            'Values': status
        }
    ]
    logging.info("Attempting to create a list of instances")

    try:

        for instance in ec2.instances.filter(Filters=filters):
            instance_list.append(instance)
            try:
                for tag in instance.tags:  # As AWS stores tags as key and value
                    print("[%d]" % (i) + instance.id + " Tag Key: " + tag['Key'] + " Value: " + tag['Value'])
            except:
                print("[%d]" % (i) + instance.id + " No Tags")
            logging.info(instance.id + instance.instance_type)
            i += 1
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    return instance_list
def quitInstance():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])   #function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        instance_menu()
    else:
        choice = input("""Please select the instance number to terminate:""")
        try:
            selectedinstance = instance_list[
                int(choice)]  # access the object returned for the selected instance
            print("The instance to be terminated is the following: " + selectedinstance.id)
            print("Please be patient")
            logging.info("The instance to be terminated is the following: " + selectedinstance.id)
            response = selectedinstance.terminate()
            logging.info(response)
            print(response)  # Printing the instance that has been terminated
            input("\nPress Enter to continue...")
            instance_menu()
        except Exception as error:
            print(error)
            logging.warning("Issue with choice entry to terminate an instance")
            print("Incorrect choice, please try again")
            input("\nPress Enter to continue...")
            instance_menu()
def select_monitor():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])   #function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        monitor_menu()
    else:
        choice = input("""Please select the instance number to monitor:""")

        try:
            selectedinstance = instance_list[int(choice)]
            selectedinstance.monitor()
            metric_iterator = cloudwatch.metrics.filter(Namespace='AWS/EC2',
                                                        MetricName='CPUUtilization',
                                                        Dimensions=[{'Name':'InstanceId', 'Value': selectedinstance.id}])
            metric = list(metric_iterator)[0]    # extract first (only) element
            response = metric.get_statistics(StartTime = datetime.utcnow() - timedelta(minutes=5),   # 5 minutes ago
                                             EndTime=datetime.utcnow(),                              # now
                                             Period=300,                                             # 5 min intervals
                                             Statistics=['Average'])
            print ("Average CPU utilisation:", response['Datapoints'][0]['Average'], response['Datapoints'][0]['Unit'])
            # print (response)
            input("\nPress Enter to continue...")
            if choice == "R" or choice == "r":
                select_monitor()
            else:
               monitor_menu()
        except Exception as e:
            print(e)
            logging.warning("Issue with choice entry as no data yet for the instance")
            print("Issue with choice entry as no data yet for the instance")
            choice = input("\nPress Enter to continue...or R to repeat")
            if choice == "R" or choice == "r":
                select_monitor()
            else:
               monitor_menu()
def cloudwatch_alarm():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])   #function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        monitor_menu()
    else:
        choice = input("""Please select the instance number to monitor:""")
        print(choice)
        try:
            selectedinstance = instance_list[int(choice)]
            selectedinstance.monitor()
            cloudwatch_client = boto3.client('cloudwatch')
            #https://boto3.amazonaws.com/v1/documentation/api/latest/guide/cw-example-creating-alarms.html
            response = cloudwatch_client.put_metric_alarm(
                 AlarmName='Web_Server_CPU_Utilization',
                 AlarmActions=['arn:aws:sns:eu-west-1:013355473762:test',],   #this arn will send an email to my email account
                 ComparisonOperator='LessThanThreshold',
                 EvaluationPeriods=1,
                 MetricName='CPUUtilization',
                 Namespace='AWS/EC2',
                 Period=60,
                 Statistic='Average',
                 Threshold=20.0,
                 ActionsEnabled=False,
                 AlarmDescription='Alarm when server CPU lower than 20%',   #very low for example for assignment
                 Dimensions=[
                     {
                     'Name': 'InstanceId',
                     'Value': selectedinstance.id
                     },
                 ],
                 Unit='Seconds'
            )
            print(response)
            response2 = cloudwatch_client.describe_alarm_history(
                 AlarmName='Web_Server_CPU_Utilization',
                 HistoryItemType='Action',
                 StartDate=datetime(2015, 1, 1),
                 EndDate=datetime(2022, 1, 1),
                 MaxRecords=55,
            )
            print(response2)
            logging.info(response2)
            input("\nPress Enter to continue...")
            monitor_menu()
        except Exception as e:
            print(e)
            logging.warning(e)
            print("Incorrect choice, please try again")
            input("\nPress Enter to continue...")
            monitor_menu()
def cpu_utilisation(usage):
    instance_list = []
    try:
        instance_list = instance_listing(['running'])   #function that takes in the instance status and returns an arrany of instance id's
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")
    if not instance_list:  # check for an empty array i.e. no running instances
        print("No running instances")
        logging.info("No running instances")
        monitor_menu()
    else:
        choice = input("""Please select the instance number to monitor:""")
        print(choice)
        try:
             selectedinstance = instance_list[int(choice)]
             ssh_text = "ssh -o StrictHostkeyChecking=no -i kp2020.pem ec2-user@"

        except Exception as e:
            print(e)
            logging.warning(e)
            print("Incorrect choice, please try again")
            input("\nPress Enter to continue...")
            monitor_menu()
def open_logfile():
    try:
        subprocess.call('nano log/aws_assignment.log', shell=True)
        input("\nPress Enter to continue...")
        main()

    except Exception as e:
        print(e)
        input("\nPress Enter to continue...")
        main()
def pushmonitoring():
    instance_list = []
    try:
        instance_list = instance_listing(['running'])
    except:
        logging.warning("Couldn't create a list of instances")
        print("Error searching for instances:")

    if not instance_list:
        logging.warning("No running instances")
        print("No running instances")
        input("\nPress Enter to continue...")
        monitor_menu()
    else:
        choice = input("""Which instance would you like to setup a server on?""")
        print(choice)
        try:
            selected_instance = instance_list[int(choice)]
            ssh_text = "ssh -o StrictHostkeyChecking=no -i kp2020.pem ec2-user@"
            selected_instance.monitor() #enabled detailed monitoring
            subprocess.run("scp -i kp2020.pem credentials ec2-user@" + selected_instance.public_ip_address + ":.",
                                   shell=True)  # scp to copy the monitoring file to the webserver
            subprocess.run("scp -i kp2020.pem config ec2-user@" + selected_instance.public_ip_address + ":.",
                                   shell=True)  # scp to copy the monitoring file to the webserver
            subprocess.run(
                ssh_text + selected_instance.public_ip_address + " \ 'mkdir ~/.aws; mv credentials ~/.aws/credentials; mv config ~/.aws/config'",
                shell=True) #move the credentials and aws config files to the required folders
            #create a file call mem.sh
            f = open("mem.sh", "w+")
            f.write("#!/bin/bash\n")
            f.write("USEDMEMORY=$(free -m | awk 'NR==2{printf \"%.2f\t\", $3*100/$2 }')\n")
            f.write("TCP_CONN=$(netstat -an | wc -l)\n")
            f.write("TCP_CONN_PORT_80=$(netstat -an | grep 80 | wc -l)\n")
            f.write("USERS=$(uptime |awk '{ print $6 }')\n")
            f.write("IO_WAIT=$(iostat | awk 'NR==4 {print $5}')\n")
            f.write("instance_id=" + selected_instance.id+"\n")
            f.write("aws cloudwatch put-metric-data --metric-name memory-usage --dimensions Instance=$instance_id  --namespace \"Custom\" --value $USEDMEMORY\n")
            f.write("aws cloudwatch put-metric-data --metric-name Tcp_connections --dimensions Instance=$instance_id  --namespace \"Custom\" --value $TCP_CONN\n")
            f.write("aws cloudwatch put-metric-data --metric-name TCP_connection_on_port_80 --dimensions Instance=$instance_id  --namespace \"Custom\" --value $TCP_CONN_PORT_80\n")
            f.write("aws cloudwatch put-metric-data --metric-name IO_WAIT --dimensions Instance=$instance_id --namespace \"Custom\" --value $IO_WAIT\n")
            f.close()
            subprocess.run("scp -i kp2020.pem mem.sh ec2-user@" + selected_instance.public_ip_address + ":.",
                                   shell=True)  # scp to copy the monitoring file to the webserver
            subprocess.run("scp -i kp2020.pem cron.sh ec2-user@" + selected_instance.public_ip_address + ":.",
                                   shell=True)  # scp to copy the cronjob file to the webserver
            subprocess.run(
                ssh_text + selected_instance.public_ip_address + " \ 'chmod +x mem.sh; chmod +x cron.sh; ./mem.sh;sudo ./cron.sh'",
                shell=True) #change the permissions on the mem.sh and cron files and run both


            input("\nPress Enter to continue...")
            monitor_menu()
        except:
            logging.warning("Issue with choice entry to select an instance")
            print("Incorrect choice, as server may not be fully loaded,  please try again thanks")
            input("\nPress Enter to continue...")
            monitor_menu()

main()
