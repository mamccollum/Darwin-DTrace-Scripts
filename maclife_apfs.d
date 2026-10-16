#!/usr/sbin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
	printf("%-12s %6s %6s %-12.12s %-16s %s\n", "TIME(ms)", "UID",
	    "PID", "PROCESS", "CALL", "DIR/FILE");
}

/* see sys/bsd/sys/vnode_if.h */

fbt::apfs_vnop_create:entry,
fbt::apfs_vnop_remove:entry
{
    this->args = (struct vnop_create_args *)arg0;
    this->dvp  = (struct vnode *)this->args->a_dvp;
    this->cnp  = (struct componentname *)this->args->a_cnp;
    this->path = this->dvp->v_name;
    this->name = this->cnp->cn_nameptr;

    printf("%-12d %6d %6d %-12.12s %-12s %s/%s\n",
        timestamp / 1000000, uid, pid, execname, probefunc,
        this->path != NULL ? stringof(this->path) : "<null>",
        stringof(this->name));
}
