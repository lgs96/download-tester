#!/bin/bash

# Check if IP address argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ip_address>"
    exit 1
fi

IP_ADDRESS="$1"

echo "Filtering for IP address: $IP_ADDRESS"

# Convert IP address to hex
IP_HEX=$(printf '%02X' ${IP_ADDRESS//./ })
IP_HEX_REVERSED="0x${IP_HEX:6:2}${IP_HEX:4:2}${IP_HEX:2:2}${IP_HEX:0:2}"

# Start BPF tracing
sudo bpftrace -e '
tracepoint:tcp:tcp_probe
{
    $target_ip = '$IP_HEX_REVERSED';
    $daddr_hex = (uint32)(args->daddr[20]) |
                 ((uint32)(args->daddr[21]) << 8) |
                 ((uint32)(args->daddr[22]) << 16) |
                 ((uint32)(args->daddr[23]) << 24);

    // Print all daddr bytes from 0 to 27 manually
    printf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           args->daddr[0], args->daddr[1], args->daddr[2], args->daddr[3],
           args->daddr[4], args->daddr[5], args->daddr[6], args->daddr[7],
           args->daddr[8], args->daddr[9], args->daddr[10], args->daddr[11],
           args->daddr[12], args->daddr[13], args->daddr[14], args->daddr[15],
           args->daddr[16], args->daddr[17], args->daddr[18], args->daddr[19],
           args->daddr[20], args->daddr[21], args->daddr[22], args->daddr[23],
           args->daddr[24], args->daddr[25], args->daddr[26], args->daddr[27]);
}'
