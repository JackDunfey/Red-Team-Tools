#!/bin/sh

# This script installs the necessary libraries and development tools for raw socket programming in FreeBSD

# Update package repository information
echo "Updating package repository information..."
pkg update

# Install essential build tools
echo "Installing essential build tools..."
pkg install -y gcc make gdb

# Install development libraries for raw socket programming
echo "Installing development libraries..."
pkg install -y libpcap netinet

# Install the FreeBSD kernel headers (this will include headers like netinet/ether.h)
echo "Installing kernel headers..."
pkg install -y freebsd-kernel-source

# Check if the necessary libraries are installed
echo "Checking if the necessary libraries are installed..."
if ! pkg info | grep -q "libpcap"; then
  echo "libpcap not found. Installing..."
  pkg install -y libpcap
fi

if ! pkg info | grep -q "netinet"; then
  echo "netinet not found. Installing..."
  pkg install -y netinet
fi

# Verify installation of packages
echo "Verifying the installation of required packages..."
pkg info | grep -E "gcc|make|gdb|libpcap|netinet"

echo "Setup complete. You should now be able to compile and run raw socket programs."
