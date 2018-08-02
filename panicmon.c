#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/net.h>
#include <net/sock.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm/uaccess.h>
#include <linux/socket.h>
#include <linux/slab.h>


#define MODULENAME "panicmon"

static char *desturi = NULL;
module_param(desturi, charp, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(desturi, "destination URI, multi URIs "
	"should be seprated by ,\n");


#define PORT 7


u32 create_address(u8 *ip)
{
	u32 addr = 0;
	int i;

	for(i = 0; i < 4; i++) {
		addr += ip[i];
		if(i == 3)
			break;
		addr <<= 8;
	}

	return addr;
}


int sock_send(struct socket *sock, char *buf, size_t length, unsigned long flags)
{
	struct msghdr msg;
	struct kvec vec;
	int ret, written = 0, left = length;
	mm_segment_t oldmm;

	msg.msg_name    = 0;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags   = flags;

	oldmm = get_fs();
	set_fs(KERNEL_DS);

repeat_send:
	vec.iov_len = left;
	vec.iov_base = (char *)buf + written;

	ret = kernel_sendmsg(sock, &msg, &vec, left, left);
	if((ret == -ERESTARTSYS) || (!(flags & MSG_DONTWAIT) && (ret == -EAGAIN)))
		goto repeat_send;
	else if(ret > 0) {
		written += ret;
		left -= ret;
		if(left)
			goto repeat_send;
	} else {
		pr_err("%s kernel_sendmsg error, ret = %d\n", MODULENAME, ret);
		set_fs(oldmm);
		return ret;
	}

	set_fs(oldmm);
	return written;
}


static int __tcp_sendto_uri(char *msg)
{
	struct socket *tcp_socket = NULL;
	struct sockaddr_in saddr;
	unsigned char destip[5] = {192, 168, 56, 102, '\0'};
	char *reply = kmalloc(4096, GFP_KERNEL);
	int ret = -1;

	//ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &tcp_socket);
	ret = sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &tcp_socket);
	if(ret < 0) {
		pr_err("%s sock_create error, ret = %d\n", MODULENAME, ret);
		goto out;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(PORT);
	saddr.sin_addr.s_addr = htonl(create_address(destip));

	ret = tcp_socket->ops->connect(tcp_socket, (struct sockaddr *)&saddr,
			sizeof(saddr), O_RDWR);
	if(ret) {
		pr_err("%s sock connect error, ret = %d\n", MODULENAME, ret);
		goto release_sock;
	}

	sock_send(tcp_socket, msg, strlen(msg), MSG_DONTWAIT);

release_sock:
	if(tcp_socket != NULL) {
		sock_release(tcp_socket);
		tcp_socket = NULL;
	}

out :
	return ret;
}

static int panicmon_notify(struct notifier_block *nb, unsigned long code, 
	void *unused)
{
	__tcp_sendto_uri("panic");
	return NOTIFY_DONE;
}


static struct notifier_block panicmon_nb = {
	.notifier_call = panicmon_notify,
	.priority = 1,
};


static int __init panicmon_init(void)
{
	pr_info("%s init\n", MODULENAME);
	atomic_notifier_chain_register(&panic_notifier_list, &panicmon_nb);

	return 0;
}

static void __exit panicmon_exit(void)
{
	pr_info("%s exit\n", MODULENAME);
	atomic_notifier_chain_unregister(&panic_notifier_list, &panicmon_nb);
	pr_info("desturi %s\n", desturi);
}


module_init(panicmon_init)
module_exit(panicmon_exit)


MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhenwei pi");
