#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h> // for if_nametoindex

#include <bpf/libbpf.h> // for libbpf functions
#include <bpf/bpf.h>    // for BPF system calls

static int ifindex = -1;
static __u32 xdp_flags = 0;
static const char *ifname = NULL;
static const char *bpf_file_path = NULL;

static void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -i <ifname> -f <bpf_file.o>\n", prog_name);
    fprintf(stderr, "  -i <ifname>: Network interface name (e.g., eth0)\n");
    fprintf(stderr, "  -f <bpf_file.o>: Path to the compiled BPF object file\n");
    fprintf(stderr, "  -U (Optional): Unload XDP program\n");
}

static int xdp_set_link(int ifindex, __u32 flags, int fd) {
    int err;
    if (fd >= 0) { // Load XDP program
        err = bpf_set_link_xdp_fd(ifindex, fd, flags);
    } else { // Unload XDP program
        err = bpf_set_link_xdp_fd(ifindex, -1, flags);
    }

    if (err) {
        fprintf(stderr, "ERROR: %s, code %d (%s)\n",
                fd >= 0 ? "attaching XDP program" : "detaching XDP program",
                err, strerror(abs(err)));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int opt;
    int err;
    int prog_fd = -1;
    int unload_only = 0;

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

    if (unload_only) {
        printf("Unloading XDP program from %s (ifindex: %d)...\n", ifname, ifindex);
        return xdp_set_link(ifindex, xdp_flags, -1);
    }

    if (bpf_file_path == NULL) {
        usage(argv[0]);
        return 1;
    }

    // Load BPF object file
    obj = bpf_object__open_file(bpf_file_path, NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: bpf_object__open_file failed: %s\n", strerror(errno));
        return 1;
    }

    // Load BPF object into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: bpf_object__load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    // Get the XDP program from the object
    prog = bpf_object__find_program_by_name(obj, "xdp_drop_prog");
    if (!prog) {
        fprintf(stderr, "ERROR: finding XDP program 'xdp_drop_prog' in %s\n", bpf_file_path);
        bpf_object__close(obj);
        return 1;
    }

    // Get the file descriptor of the program
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "ERROR: bpf_program__fd failed\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach XDP program to the interface
    printf("Attaching XDP program to %s (ifindex: %d)...\n", ifname, ifindex);
    err = xdp_set_link(ifindex, xdp_flags, prog_fd);
    if (err) {
        bpf_object__close(obj);
        return 1;
    }

    printf("XDP program successfully loaded and attached.\n");
    printf("To detach, run: %s -i %s -U\n", argv[0], ifname);
    printf("To see kernel debug messages: sudo dmesg -w\n");
    printf("Press Ctrl+C to detach and exit.\n");

    // Keep program running until Ctrl+C
    while (1) {
        sleep(1);
    }

    // Detach XDP program on exit (Ctrl+C will trigger this)
    printf("\nDetaching XDP program from %s...\n", ifname);
    xdp_set_link(ifindex, xdp_flags, -1);
    bpf_object__close(obj);

    return 0;
}
