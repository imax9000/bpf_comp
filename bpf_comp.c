#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sysexits.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

int snaplen = 0xffff;
int dlt = DLT_RAW;

enum
{
	RAW,
	HEXSTRING,
	NG_BPF
};

int format = HEXSTRING;

char *expr = NULL;

void
usage(FILE *f, char *name)
{
	fprintf(f, "Usage: %s [options] expression\n\n", name);
	fprintf(f, "Options:\n");
	fprintf(f, "  -h\t - print this text and exit\n");
	fprintf(f, "  -l number\t - link type (default: DLT_RAW)\n");
	fprintf(f, "  -s number\t - snapshot length (default: 0xffff)\n");
	fprintf(f, "  -o [r|h|n]\t - output format (default: h)\n");
	fprintf(f, "\tr - raw\n\th - hexdump\n\tn - ng_bpf\n");
}

void
parse_args(int argc, char *argv[])
{
	char c;
	char *progname = argv[0];
	int i;
	size_t len;

	while((c = getopt(argc, argv, "hl:s:o:")) != -1)
	{
		switch(c)
		{
		case 'h':
			usage(stdout, progname);
			exit(EX_OK);
			break;
		case 'l':
			if ((dlt = strtol(optarg, NULL, 0)) == 0 && errno != 0)
			{
				fprintf(stderr, "Failed to parse %s: %s\n", optarg, strerror(errno));
				exit(EX_USAGE);
			}
			break;
		case 's':
			if ((dlt = strtol(optarg, NULL, 0)) == 0 && errno != 0)
			{
				fprintf(stderr, "Failed to parse %s: %s\n", optarg, strerror(errno));
				exit(EX_USAGE);
			}
			break;
		case 'o':
			switch(optarg[0])
			{
			case 'r':
				format = RAW;
				break;
			case 'h':
				format = HEXSTRING;
				break;
			case 'n':
				format = NG_BPF;
				break;
			default:
				fprintf(stderr, "Unknown format: %c\n", optarg[0]);
				usage(stderr, progname);
				exit(EX_USAGE);
				break;
			}
			break;
		default:
			usage(stderr, progname);
			exit(EX_USAGE);
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc == 0)
	{
		fprintf(stderr, "Expression expected\n");
		usage(stderr, progname);
		exit(EX_USAGE);
	}

	len = argc;
	for(i = 0; i < argc; i++)
		len += strlen(argv[i]);

	expr = malloc(len);
	if (expr == NULL)
		exit(EX_SOFTWARE);
	expr[0] = '\0';
	strcat(expr, argv[0]);
	for(i = 1; i < argc; i++)
	{
		strcat(expr, " ");
		strcat(expr, argv[i]);
	}
}

void
print_raw(const struct bpf_program *prog)
{
	size_t i;
	for(i = 0; i < prog->bf_len; i++)
	{
		putchar(prog->bf_insns[i].code >> 8);
		putchar(prog->bf_insns[i].code & 0xff);
		putchar(prog->bf_insns[i].jt);
		putchar(prog->bf_insns[i].jf);
		putchar(prog->bf_insns[i].k >> 24);
		putchar((prog->bf_insns[i].k >> 16) & 0xff);
		putchar((prog->bf_insns[i].k >> 8) & 0xff);
		putchar(prog->bf_insns[i].k & 0xff);
	}
}

void
print_hexstring(const struct bpf_program *prog)
{
	size_t i;
	for(i = 0; i < prog->bf_len; i++)
	{
		printf("%02X", prog->bf_insns[i].code >> 8);
		printf("%02X", prog->bf_insns[i].code & 0xff);
		printf("%02X", prog->bf_insns[i].jt);
		printf("%02X", prog->bf_insns[i].jf);
		printf("%02X", prog->bf_insns[i].k >> 24);
		printf("%02X", (prog->bf_insns[i].k >> 16) & 0xff);
		printf("%02X", (prog->bf_insns[i].k >> 8) & 0xff);
		printf("%02X", prog->bf_insns[i].k & 0xff);
	}
	printf("\n");
}

void
print_ng_bpf(const struct bpf_program *prog)
{
	size_t i;
	printf("bpf_prog_len=%d bpf_prog=[ ", prog->bf_len);

	for (i = 0; i < prog->bf_len; i++)
	{
		printf("{ code=%d jt=%d jf=%d k=%d } ", prog->bf_insns[i].code, prog->bf_insns[i].jt, prog->bf_insns[i].jf, prog->bf_insns[i].k);
	}
	printf("]\n");
}

int
main(int argc, char *argv[])
{
	struct bpf_program prog;
	parse_args(argc, argv);

	if (pcap_compile_nopcap(snaplen, dlt, &prog, expr, 1, 0))
	{
		fprintf(stderr, "Syntax error in expression\n");
		exit(EX_USAGE);
	}

	switch(format)
	{
	case RAW:
		print_raw(&prog);
		break;
	case HEXSTRING:
		print_hexstring(&prog);
		break;
	case NG_BPF:
		print_ng_bpf(&prog);
		break;
	}

	return EX_OK;
}
