#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h> // for if_nametoindex

#include <bpf/libbpf.h> // libbpf functions for opening, loading, attaching BPF programs
#include <bpf/bpf.h>    // for BPF system calls (though libbpf generally wraps these)

// Netlink 관련 헤더 추가
#include <linux/netlink.h>
#include <linux/rtnetlink.h> // RTM_SETLINK, IFLA_XDP 등의 정의 포함
// #include <linux/if_link.h> // xdp_link_info가 여기서 정의되지 않아 주석 처리합니다.

// Netlink 메시지 구성을 위한 매크로 정의 (표준 헤더에 없을 수 있음)
#ifndef RTA_ALIGN
#define RTA_ALIGN(len) (((len) + 3) & ~3)
#endif
#ifndef RTA_LENGTH
#define RTA_LENGTH(len) (RTA_ALIGN(sizeof(struct rtattr)) + (len))
#endif
#ifndef RTA_DATA
#define RTA_DATA(rta) ((void *)(((char *)(rta)) + RTA_ALIGN(sizeof(struct rtattr))))
#endif

// IFLA_XDP_UNSPEC이 없어 아래 정의가 필요한 경우
#ifndef IFLA_XDP_UNSPEC
#define IFLA_XDP_UNSPEC             0
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD                 1
#endif
#ifndef IFLA_XDP_ATTACHED
#define IFLA_XDP_ATTACHED           2
#endif
#ifndef IFLA_XDP_FLAGS
#define IFLA_XDP_FLAGS              3
#endif
#ifndef IFLA_XDP_PROG_ID
#define IFLA_XDP_PROG_ID            4
#endif
#ifndef IFLA_XDP_DRV_METADATA
#define IFLA_XDP_DRV_METADATA       5
#endif
#ifndef IFLA_XDP_UNALIGNED_BUF_ADDR
#define IFLA_XDP_UNALIGNED_BUF_ADDR 6
#endif
#ifndef IFLA_XDP_UNALIGNED_BUF_SIZE
#define IFLA_XDP_UNALIGNED_BUF_SIZE 7
#endif
#ifndef IFLA_XDP_MEM_INFO
#define IFLA_XDP_MEM_INFO           8
#endif
#ifndef IFLA_XDP_ACTS
#define IFLA_XDP_ACTS               9
#endif
#ifndef IFLA_XDP_ATTR_MAX
#define IFLA_XDP_ATTR_MAX           10
#endif


static int ifindex = -1;
static __u32 xdp_flags = 0; // 이 변수는 현재 사용되지 않으므로 경고가 나올 수 있습니다. (무시 가능)
static const char *ifname = NULL;
static const char *bpf_file_path = NULL;

static void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -i <ifname> -f <bpf_file.o>\n", prog_name);
    fprintf(stderr, "  -i <ifname>: Network interface name (e.g., eth0)\n");
    fprintf(stderr, "  -f <bpf_file.o>: Path to the compiled BPF object file\n");
    fprintf(stderr, "  -U (Optional): Unload XDP program\n");
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int opt;
    int err;
    int unload_only = 0;

    // Netlink 소켓 및 메시지 관련 변수
    struct sockaddr_nl sa;
    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
        char attrbuf[512]; // 속성 버퍼
    } req;
    int nl_sock_fd = -1;

    while ((opt = getopt(argc, argv, "i:f:U")) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            case 'f':
                bpf_file_path = optarg;
                break;
            case 'U':
                unload_only = 1;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (ifname == NULL) {
        usage(argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "ERROR: Invalid interface name: %s\n", ifname);
        return 1;
    }

    // Netlink 소켓 생성
    nl_sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_sock_fd < 0) {
        perror("ERROR: Failed to create netlink socket");
        return 1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(nl_sock_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("ERROR: Failed to bind netlink socket");
        close(nl_sock_fd);
        return 1;
    }

    // XDP 프로그램 언로드 로직 (Netlink 사용)
    if (unload_only) {
        printf("Unloading XDP program from %s (ifindex: %d)...\n", ifname, ifindex);

        memset(&req, 0, sizeof(req));
        req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
        req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        req.nlh.nlmsg_type = RTM_SETLINK;
        req.ifm.ifi_family = AF_UNSPEC;
        req.ifm.ifi_index = ifindex;

        struct rtattr *xdp_outer_attr = (struct rtattr *)req.attrbuf;
        xdp_outer_attr->rta_type = IFLA_XDP;
        // XDP 프로그램을 제거할 때는 IFLA_XDP_FD를 -1로 설정하는 것 외에
        // 추가적인 xdp_link_info 구조체의 크기는 필요 없습니다.
        // IFLA_XDP_FD 속성만 포함하여 메시지 길이를 계산합니다.
        xdp_outer_attr->rta_len = RTA_LENGTH(RTA_LENGTH(sizeof(int))); // IFLA_XDP_FD 속성의 길이

        struct rtattr *xdp_fd_attr = (struct rtattr *)RTA_DATA(xdp_outer_attr);
        xdp_fd_attr->rta_type = IFLA_XDP_FD;
        xdp_fd_attr->rta_len = RTA_LENGTH(sizeof(int));
        memcpy(RTA_DATA(xdp_fd_attr), &((int){-1}), sizeof(int)); // FD를 -1로 설정
        
        req.nlh.nlmsg_len += RTA_ALIGN(xdp_outer_attr->rta_len); // 최종 메시지 길이 조정

        // sendmsg의 두 번째 인자는 const struct msghdr * 타입을 기대합니다.
        // 임시 구조체를 생성하여 포인터를 전달합니다.
        struct msghdr msg = {
            .msg_name = &sa,
            .msg_namelen = sizeof(sa),
            .msg_iov = &(struct iovec){ .iov_base = &req, .iov_len = req.nlh.nlmsg_len },
            .msg_iovlen = 1
        };
        err = sendmsg(nl_sock_fd, &msg, 0); // <-- sendmsg 호출 수정
        if (err < 0) {
            perror("ERROR: Failed to send netlink message for unload");
            close(nl_sock_fd);
            return 1;
        }

        // Netlink 응답 수신 (ACK/NACK)
        char reply_buf[1024];
        struct nlmsghdr *reply_nlh;
        err = recv(nl_sock_fd, reply_buf, sizeof(reply_buf), 0);
        if (err < 0) {
            perror("ERROR: Failed to receive netlink reply for unload");
            close(nl_sock_fd);
            return 1;
        }
        reply_nlh = (struct nlmsghdr *)reply_buf;
        if (reply_nlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(reply_nlh);
            fprintf(stderr, "ERROR: Netlink error during unload: %s (%d)\n", strerror(abs(err_msg->error)), err_msg->error);
            close(nl_sock_fd);
            return 1;
        }

        printf("XDP program detached successfully via Netlink.\n");
        close(nl_sock_fd);
        return 0;
    }

    // XDP 프로그램 로드 로직
    if (bpf_file_path == NULL) {
        usage(argv[0]);
        close(nl_sock_fd);
        return 1;
    }

    // 1. BPF object file 열기
    obj = bpf_object__open_file(bpf_file_path, NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: bpf_object__open_file failed: %s\n", strerror(errno));
        close(nl_sock_fd);
        return 1;
    }

    // 2. BPF object를 커널에 로드
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: bpf_object__load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        close(nl_sock_fd);
        return 1;
    }

    // 3. XDP 프로그램 찾기
    //prog = bpf_object__find_program_by_name(obj, "xdp_drop_prog");
    prog = bpf_object__find_program_by_name(obj, "xdp_minimal_test");
    if (!prog) {
        fprintf(stderr, "ERROR: finding XDP program 'xdp_drop_prog' in %s\n", bpf_file_path);
        bpf_object__close(obj);
        close(nl_sock_fd);
        return 1;
    }

    // 4. XDP 프로그램을 인터페이스에 어태치 (최신 libbpf API 사용)
    link = bpf_program__attach_xdp(prog, ifindex);
    if (!link) {
        err = -errno; // libbpf 함수는 오류 발생 시 errno를 설정하고 NULL 반환
        fprintf(stderr, "ERROR: bpf_program__attach_xdp failed: %s\n", strerror(abs(err)));
        bpf_object__close(obj);
        close(nl_sock_fd);
        return 1;
    }

    printf("XDP program successfully loaded and attached to %s.\n", ifname);
    printf("To detach, run: %s -i %s -U\n", argv[0], ifname);
    printf("To see kernel debug messages: sudo dmesg -w\n");
    printf("Press Ctrl+C to detach and exit.\n");

    // Keep program running until Ctrl+C
    // Ctrl+C 시그널을 받으면 bpf_link__destroy 호출
    while (1) {
        sleep(1);
    }

    // Detach XDP program on exit (Ctrl+C will trigger this)
    printf("\nDetaching XDP program from %s...\n", ifname);
    bpf_link__destroy(link); // bpf_link 객체를 통해 detach
    bpf_object__close(obj);
    close(nl_sock_fd);

    return 0;
}
