#!/usr/sbin/dtrace -s
#pragma D option quiet
#pragma D option aggsortrev
#pragma D option aggsortpos=2

dtrace:::BEGIN
{
    CLEAR = "\033[2J\033[1;1H";
    printf("Tracing... Please wait.\n");
}

mach_trap::mach_msg2_trap:entry
{
    this->options   = arg1;
    this->send_size = (uint32_t)(arg2 >> 32);
    this->msgh_id   = (uint32_t)(arg4 >> 32);
}

mach_trap::mach_msg2_trap:entry
/this->options & 1/
{
    @count[execname, pid] = count();
    @bytes[execname, pid] = sum(this->send_size);
}

profile:::tick-1sec
{
    printf("%s", CLEAR);
    trunc(@count, 20);
    trunc(@bytes, 20);

    printf("\n%-20s %-8s %9s %12s\n", "PROCESS", "PID", "MSG COUNT", "BYTES");
    printf("%-20s %-8s %9s %12s\n",   "-------", "---", "---------", "-----");
    printa("%-20s %-8d %@9d %@12d\n", @count, @bytes);

    clear(@count);
    clear(@bytes);
}

dtrace:::END
{
    trunc(@count);
    trunc(@bytes);
}
