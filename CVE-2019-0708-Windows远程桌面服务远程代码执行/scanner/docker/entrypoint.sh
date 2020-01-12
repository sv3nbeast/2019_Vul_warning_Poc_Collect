#!/bin/bash
Xvfb :99 -screen 0 1024x768x16 &

# Check if Xvfb has started correctly yet or
# if we have to sleep for a while.
for i in {0..10}; do
    if [[ ! -d /tmp/.X11-unix ]]; then
        sleep 0.1
    else
        break
    fi
done

# Use exec here so that we can send signals to abort
exec /opt/rdesktop/rdesktop "${1}"
