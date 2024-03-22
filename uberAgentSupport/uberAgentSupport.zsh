#!/bin/zsh

#########################################################################
#                                                                       #
# Script Name: uberAgentSupport.zsh                                     #
# Version:     1.0.0                                                    #
# Date:        2024-03-22                                               #
# Author:      uberAgent Support Team                                   #
# Company:     vast limits GmbH                                         #
#                                                                       #
# Description:                                                          #
# This script gathers key logs and UberAgent configuration files from   #
# your system into a single support bundle. This bundle assists in      #
# diagnosing and addressing any potential issues with the product       #
# The bundle includes user logs, crash reports, configuration files,    #
# and folder permissions.                                               #
#                                                                       #
# Usage:                                                                #
# The script must be run with root privileges.                          #
# The compressed bundle is placed on the desktop of the useraccount     #
# that executed the script.                                             #
#                                                                       #
# sudo ./uberAgentSupport.zsh                                           #
#                                                                       #
#########################################################################

# Define path to Desktop, hostname and timestamp for better readability and reusability
desktopPath="$HOME/Desktop"
hostname=$(hostname)
timestamp=$(date "+%Y-%m-%d_%H-%M-%S")

# Initialize a variable for results storage
# The path includes the current timestamp for uniqueness
bundlePath="${desktopPath}/uASupportBundle-${hostname}-${timestamp}"

# Check root access: exit the script if the user is not root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root."
   exit 1
fi

# Create a structured directory tree inside the bundle path
mkdir -p "${bundlePath}"/{Config/Local,Config/CCFM,Logs/Daemon,Logs/Users,CrashReports}

# Define a log file path inside the bundle
logPath="${bundlePath}/uASupportBundleLog.txt"

# Redirect all future command outputs(both stdout and stderr) to the specified log file
exec > >(tee -a $logPath) 2>&1

# Start copying desired files
echo "Collecting files..."
cp -R /Library/Logs/uberAgent/* "${bundlePath}/Logs/Daemon/"

# Make sure to copy user-specific logs 
for dir in /Users/*/
do
    username=$(basename $dir)
    if [ -d "${dir}Library/Logs/uberAgent/" ]; then
        mkdir -p "${bundlePath}/Logs/Users/${username}"
        cp -R "${dir}Library/Logs/uberAgent/" "${bundlePath}/Logs/Users/${username}/"
    fi
done

# Check and log permissions of uberAgent's Application Support directory
echo "Checking folder permissions..."
ls -la /Library/Application\ Support/uberAgent/ > "${bundlePath}/Config/folder_permissions.txt"

# Find and copy .conf files
echo "Copying .conf files..."
find /Library/Application\ Support/uberAgent/ -name "*.conf" -exec cp {} "${bundlePath}/Config/Local/" \;

# Check if 'Security inventory' is directory and if true, copy 'Security inventory' directory
if [ -d "/Library/Application Support/uberAgent/Security inventory" ]; then
    echo "Copying Security inventory folder..."
    cp -R "/Library/Application Support/uberAgent/Security inventory" "${bundlePath}/Config/Local/"
fi

# Check if uberAgent-remote-config-macOS.conf exists and if true, copy 'Config Cache' directory 
if [ -f "/Library/Application Support/uberAgent/uberAgent-remote-config-macOS.conf" ]; then
    if [ -d "/Library/Application Support/uberAgent/Config Cache" ]; then
        cp -R "/Library/Application Support/uberAgent/Config Cache" "${bundlePath}/Config/CCFM/"
    fi
fi

# Find and copy crash reports
echo "Collecting crash reports..."
find /Library/Logs/DiagnosticReports/ -type f \( -name "uberAgent*.ips" -o -name "uberAgent*.crash" \) -exec cp {} "${bundlePath}/CrashReports/" \;

# Compress the directory containing all the copied files and logs into a single bundle
echo "Compressing the bundle..."
cd $desktopPath
tar -czf "uASupportBundle-${hostname}-${timestamp}.tar.gz" "uASupportBundle-${hostname}-${timestamp}"
echo "Support bundle has been created successfully at ${PWD}/uASupportBundle-${hostname}-${timestamp}.tar.gz"

# Clean up the intermediate step directory
rm -rf ${bundlePath}

# Print acknowledgement of successful script completion
echo "End of script"