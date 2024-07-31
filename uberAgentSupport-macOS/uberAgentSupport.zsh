#!/bin/zsh

#########################################################################
#                                                                       #
# Script Name: uberAgentSupport.zsh                                     #
# Version:     1.1.0                                                    #
# Date:        2024-07-31                                               #
# Author:      uberAgent Team                                           #
# Company:     Citrix, Cloud Software Group                             #
#                                                                       #
# Description:                                                          #
# This script gathers logs and uberAgent configuration files from       #
# your system and creates a single support bundle. This bundle assists  #
# in diagnosing and addressing any potential issues with the product.   #
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

# Define path to desktop, hostname and timestamp for better readability and reusability
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
mkdir -p "${bundlePath}"/{Config/Local,Config/CCFM,Logs/Daemon,Logs/Users,Logs/Remote,CrashReports}

# Define a log file path inside the bundle
scriptLogPath="${bundlePath}/uASupportBundleLog.txt"

# Redirect all future command outputs (both stdout and stderr) to the specified log file
exec > >(tee -a $scriptLogPath) 2>&1

# Function to collect log files from either default or specified path
collectLogs() {
    local remoteLogfilePath="$1"

    if [ -d "${remoteLogfilePath}" ]; then
        echo "Collecting logs from ${remoteLogfilePath}..."
        find "${remoteLogfilePath}" -type f -name "*${hostname}*" -exec cp {} "${bundlePath}/Logs/Remote/" \;
    else
        echo "Log file path ${remoteLogfilePath} is not accessible or does not exist. Collecting logs from default locations."
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
    fi
}

# Check for meta config file and extract log file path
metaConfigFile="/Library/Application Support/uberAgent/uberAgent-meta-config.conf"
remoteLogfilePath=""

if [ -f "${metaConfigFile}" ]; then
    remoteLogfilePath=$(grep "^LogFilePath" "${metaConfigFile}" | cut -d'=' -f2 | xargs)
    if [ -z "${remoteLogfilePath}" ] || [ ! -d "${remoteLogfilePath}" ]; then
        remoteLogfilePath=""
        echo "Log file path is empty or inaccessible, using default log locations."
    else
        echo "Using log file path from meta config: ${remoteLogfilePath}"
    fi
else
    echo "Meta config file not found, using default log locations."
fi

# Start copying desired files and collect logs using the identified or default path
echo "Collecting files..."
collectLogs "${remoteLogfilePath}"

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