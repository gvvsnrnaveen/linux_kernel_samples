#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

enum {
        NAV_UNSPEC,
        NAV_MSG_RECV,
        NAV_MSG_SEND,
        __NAV_MAX
};

#define NAV_MAX (__NAV_MAX + 1)
struct nav_payload {
	uint8_t mac[6];
	uint32_t saddr;
	uint32_t daddr;
	uint32_t sport;
	uint32_t dport;
};


int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg){
	int *ret = (int*)arg;
	*ret = err->error;
	printf("Error: %d\n", err->error);
	if(err->error > 0){
		*ret = -(err->error);
	}
	return NL_SKIP;
}

int finish_handler(struct nl_msg *msg, void *arg){
	int *ret = (int*)arg;
	*ret = 0;
	return NL_SKIP;
}

int ack_handler(struct nl_msg *msg, void *arg){
	int *err = (int*)arg;
	*err = 0;
	return NL_STOP;
}

int response_handler(struct nl_msg *msg, void *data){
	printf("data received\n");
	return NL_OK;
}

int message_handler(struct nl_msg *msg, void *data){
	printf("data received in message handler\n");
	struct nav_payload mydata = {0};
	struct genlmsghdr *gnlh = (struct genlmsghdr *) nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *tb[NAV_MAX];
	nla_parse(tb, NAV_MAX, genlmsg_attrdata(gnlh, 0),genlmsg_attrlen(gnlh, 0), NULL);
	nla_memcpy(&mydata, tb[NAV_MSG_SEND], sizeof(struct nav_payload));
	struct in_addr saddr = {0}, daddr = {0};
	memcpy(&saddr, &mydata.saddr, sizeof(struct in_addr));
	memcpy(&daddr, &mydata.daddr, sizeof(struct in_addr));
	printf("received: %s, %s, %u, %u\n", strdup(inet_ntoa(saddr)), strdup(inet_ntoa(daddr)), ntohs(mydata.sport),ntohs(mydata.dport));

	return NL_OK;
}

int main(int argc, char **argv){
	struct nl_sock *nl_sk = NULL;
	int ret_val = 0;

	nl_sk = nl_socket_alloc();
	if(!nl_sk){
		printf("Failed to allocate socket\n");
		return -1;
	}
	printf("socket success\n");

	nl_socket_disable_seq_check(nl_sk);

	nl_socket_set_buffer_size(nl_sk, 256 * 1024, 0);

	ret_val = genl_connect(nl_sk);
	if(ret_val){
		printf("Failed to connect to nl\n");
		goto cleanup;
	}

	ret_val = genl_ctrl_resolve(nl_sk, "NAVCM");
	if(ret_val <= 0){
		printf("Failed to resolve nl\n");
		goto cleanup;
	}
	printf("resolution success\n");


	struct nl_cb *nl_cb = NULL;
	int err = 1;
	int res = 0;

	nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if(!nl_cb){
		printf("Failed to set callback\n");
		goto cleanup;
	}

	nl_cb_err(nl_cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
	nl_cb_set(nl_cb, NL_CB_VALID, NL_CB_CUSTOM, response_handler, NULL);
	nl_cb_set(nl_cb, NL_CB_MSG_IN, NL_CB_CUSTOM, message_handler, NULL);

	struct nl_msg *msg = nlmsg_alloc();
	if(!msg){
		printf("Failed to create msg\n");
		goto cleanup;
	}
	genlmsg_put(msg, 0, 0, ret_val, 0, 0, 1, 0);
	nl_send_auto(nl_sk, msg);
	nlmsg_free(msg);

	while (1){
		res = nl_recvmsgs(nl_sk, nl_cb);
		if(res && res != -16){
			printf("Failed: %d, %s\n", res, nl_geterror(res));
		}
	}

cleanup:
	nl_socket_free(nl_sk);
	return 0;
}
