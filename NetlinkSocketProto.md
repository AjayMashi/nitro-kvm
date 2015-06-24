This page describes the netlink socket protocol used for output

# General #
Since [r46](https://code.google.com/p/nitro-kvm/source/detail?r=46), nitro supports multi cast messages for netlink sockets. Netlink communication is enabled by defining
```
#define USE_NETLINK 1
```
in nitro.h. Comment out that line to fall back to normal kernel log buffer output. (dmesg)

# Usage #
## Kernel side ##
In order to output messages, use the `NITRO_OUTPUT(char *format, ...)` macro. Nitro manages all the netlink stuff transparently as soon as `USE_NETLINK` is enabled. Otherwise, `NITRO_OUTPUT` is just an alias for the printk-function.

## User side ##
You'll find the user space portion of the netlink communications inside of the newly created /svn/branches/netlink\_output/netlink-user directory. Just execute `./netlink-user` and it will listen for nitro broadcast messages. Be aware that the binary either needs to be run with an effective user id = 0 or by an user who has the capability `CAP_NET_ADMIN`. However, the programm checks if the conditions are met and spits out an error message otherwise.

# Details #

```
struct netlink_proto {
   u32 vm_id;
   u64 syscall_number;
   u32 rule_id;
   u32 size; //size of data
   u8 *data;
}
```

|32 bits VMID|64 bits syscall nr|32 bits total payload size|<br>
?? bits register name|8 bits format (value/deref)|32 bits size|data (size bytes)|...