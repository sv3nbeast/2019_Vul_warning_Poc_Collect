FROM debian:latest

# Copy Dockerfile as documention
COPY Dockerfile /

# Copy the script that will be used to build
# the fork of rdesktop from source.
COPY docker/setup.sh /opt/setup.sh

# The patched fork of rdesktop
COPY rdesktop-fork-bd6aa6acddf0ba640a49834807872f4cc0d0a773 /opt/rdesktop

RUN /opt/setup.sh

# This will be used by Xvfb so that rdesktop
# can run inside the container.
ENV DISPLAY :99

COPY docker/entrypoint.sh /opt/entrypoint.sh
ENTRYPOINT ["/bin/bash", "/opt/entrypoint.sh"]
