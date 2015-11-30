#!/bin/bash

DISTRO_VERSION_FILE="/proc/version"
distro=""
STING_USER_VERSION="1.0"
STING_KERNEL_VERSION="1.3"
LINUX_KERNEL_VERSION="3.4.0"

esc=$(echo -n "\033")
cc_red="${esc}[0;31m"
cc_green="${esc}[0;32m"
cc_yellow="${esc}[0;33m"
cc_blue="${esc}[0;34m"
cc_normal=`echo -n "${esc}[m\017"`

install_dbgsym ()
{

	echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" | \
	sudo tee /etc/apt/sources.list.d/ddebs.list

	echo "deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
	deb http://ddebs.ubuntu.com $(lsb_release -cs)-security main restricted universe multiverse
	deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
	sudo tee -a /etc/apt/sources.list.d/ddebs.list

	sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 428D7C01
	sudo apt-get update
	sudo apt-get install -y bash=4.3-6ubuntu1
	sudo apt-get install -y bash-dbgsym

	sudo apt-get install -y php5-dbg
}

echo_r ()
{
	if [ $# -eq 2 ]
	then
		echo $1 "${cc_red}$2${cc_normal}"
	else
		echo "${cc_red}$1${cc_normal}"
	fi
}

echo_y ()
{
	if [ $# -eq 2 ]
	then
		echo $1 "${cc_yellow}$2${cc_normal}"
	else
		echo "${cc_yellow}$1${cc_normal}"
	fi
}

echo_g ()
{
	if [ $# -eq 2 ]
	then
		echo $1 "${cc_green}$2${cc_normal}"
	else
		echo "${cc_green}$1${cc_normal}"
	fi
}

echo_y "STING needs debug versions of the bash and php5 binaries \
(with symbol table information) to support stack \
backtrace in these interpreters. You can still choose to install STING \
without interpreter support. Installing debug versions ..."

grep -i ubuntu $DISTRO_VERSION_FILE > /dev/null
if [ $? -ne 0 ]
then
       echo_y "installation script for debug binaries of bash and php5 \
currently only supports Ubuntu. For other distributions, please refer manual \
steps in the INSTALL file. "
fi

install_dbgsym

# replace dash and sh with bash
echo_y -n "Replacing sh and dash with bash (you may be prompted for \
administrator password) (press any key to continue) ... "
read s
sh_bin_path=$(which sh)
dash_bin_path=$(which dash)
bash_bin_path=$(which bash)

sudo mv $sh_bin_path $sh_bin_path.orig
ln -s $bash_bin_path $sh_bin_path

sudo mv $dash_bin_path $dash_bin_path.orig
ln -s $bash_bin_path $dash_bin_path

# echo_g "Congratulations! You have now successfully installed STING. \
# Read the USAGE file for configuration and usage information. Reboot the kernel \
# to start testing."
