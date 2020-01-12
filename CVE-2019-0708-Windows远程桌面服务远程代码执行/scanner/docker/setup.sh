export DEBIAN_FRONTEND noninteractive

# Add sources so we can get the build requirements for rdesktop
echo 'deb-src http://deb.debian.org/debian stretch main' >> /etc/apt/sources.list
echo 'deb-src http://security.debian.org/debian-security stretch/updates main' >> /etc/apt/sources.list
echo 'deb-src http://deb.debian.org/debian stretch-updates main' >> /etc/apt/sources.list

# Update the image and install common tools for debugging
apt-get update && \
    apt-get -y dist-upgrade && \
    apt-get install -y \
      iputils-ping \
      procps \
      bind9-host \
      netcat-openbsd \

# Install requirements for building rdesktop
apt-get -y build-dep rdesktop

# Install Xvfb to emulate the requirement that rdesktop
# needs to work on a regular host with a display.
apt-get -y install xvfb

# Fix for the error "Failed to open keymap xx-yy"
mkdir -p /root/.rdesktop/keymaps
cp /opt/rdesktop/keymaps/* /root/.rdesktop/keymaps/

# Start the build of the patched rdesktop fork
cd /opt/rdesktop

# Remove the pre-compiled version
rm rdesktop

./bootstrap
./configure --disable-credssp --disable-smartcard
make
