/*-------------------------------------------------------------------------
 *
 * pg_tde_master_key.c
 *	  FortressQL TDE master key management utility.
 *
 * Generates ML-KEM-768 keypairs for Transparent Data Encryption (TDE)
 * master key management.  Uses the frontend pqc-common library
 * (malloc/free, not palloc).
 *
 * Commands:
 *   init          Generate a new master key and write it to PGDATA
 *   rotate        Rotate the master key (generate new, replace old)
 *   export-pubkey Export the public key in hex
 *   info          Show information about the current master key
 *
 * Copyright (c) 2024-2026, FortressQL Contributors
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 *
 * src/bin/pg_tde_master_key/pg_tde_master_key.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres_fe.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common/logging.h"
#include "common/pqc-common.h"
#include "getopt_long.h"

#ifdef USE_PQC
#include <oqs/oqs.h>
#endif

/* ML-KEM-768 algorithm name for liboqs */
#define PQC_TDE_KEM_ALGORITHM	"ML-KEM-768"

/* Relative paths under PGDATA */
#define PQC_TDE_ENCRYPTION_DIR	"global/pg_encryption"
#define PQC_TDE_MASTER_KEY_FILE	"global/pg_encryption/master.key"
#define PQC_TDE_PUBLIC_KEY_FILE	"global/pg_encryption/master.pub"

/* Master key file header magic and version */
#define PQC_TDE_KEY_MAGIC		0x46514D4B	/* "FQMK" */
#define PQC_TDE_KEY_VERSION		1

/*
 * On-disk master key file format.
 */
typedef struct PqcTdeMasterKeyHeader
{
	uint32_t	magic;
	uint32_t	version;
	uint32_t	algorithm_id;		/* reserved for future algorithms */
	uint32_t	public_key_len;
	uint32_t	creation_time;		/* unix timestamp */
	uint32_t	rotation_count;
	uint8_t		reserved[8];		/* padding for alignment */
	/* followed by public_key_len bytes of public key */
} PqcTdeMasterKeyHeader;

static const char *progname;

static void usage(void);
static int	cmd_init(const char *datadir, bool force);
static int	cmd_rotate(const char *datadir);
static int	cmd_export_pubkey(const char *datadir);
static int	cmd_info(const char *datadir);
static void bytes_to_hex(const uint8_t *data, size_t len,
						 char *hex, size_t hex_len);
static int	hex_to_bytes(const char *hex, uint8_t *data, size_t data_len);
static int	ensure_directory(const char *path);
static int	write_secure_file(const char *path, const void *data, size_t len);
static int	read_file_to_buf(const char *path, uint8_t **buf, size_t *len);
static int	write_master_key_files(const char *datadir,
								   const uint8_t *public_key, size_t pk_len,
								   uint32_t rotation_count);

static void
usage(void)
{
	printf(_("%s manages TDE master keys for FortressQL.\n\n"), progname);
	printf(_("Usage:\n"));
	printf(_("  %s init [-D DATADIR]\n"), progname);
	printf(_("  %s rotate [-D DATADIR]\n"), progname);
	printf(_("  %s export-pubkey [-D DATADIR]\n"), progname);
	printf(_("  %s info [-D DATADIR]\n"), progname);
	printf(_("\nCommands:\n"));
	printf(_("  init          generate a new ML-KEM-768 master keypair\n"));
	printf(_("  rotate        rotate the master key (generate new keypair)\n"));
	printf(_("  export-pubkey export the public key in hex encoding\n"));
	printf(_("  info          show master key information\n"));
	printf(_("\nOptions:\n"));
	printf(_("  -D, --pgdata=DATADIR  data directory\n"));
	printf(_("  -f, --force           overwrite existing master key without prompting\n"));
	printf(_("  -V, --version         output version information, then exit\n"));
	printf(_("  -?, --help            show this help, then exit\n"));
	printf(_("\nIf no data directory (DATADIR) is specified, "
			 "the environment variable PGDATA\nis used.\n\n"));
	printf(_("The KEM secret key is printed to stdout in hex encoding.\n"));
	printf(_("Set FORTRESSQL_KEM_SECRET_KEY to this value for TDE operations.\n\n"));
	printf(_("Report bugs to <%s>.\n"), PACKAGE_BUGREPORT);
	printf(_("%s home page: <%s>\n"), PACKAGE_NAME, PACKAGE_URL);
}

int
main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"pgdata", required_argument, NULL, 'D'},
		{"force", no_argument, NULL, 'f'},
		{"version", no_argument, NULL, 'V'},
		{"help", no_argument, NULL, '?'},
		{NULL, 0, NULL, 0}
	};

	const char *datadir = NULL;
	const char *command = NULL;
	bool		force = false;
	int			c;
	int			ret;

	pg_logging_init(argv[0]);
	progname = get_progname(argv[0]);
	set_pglocale_pgservice(argv[0], PG_TEXTDOMAIN("pg_tde_master_key"));

	if (argc > 1)
	{
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
		{
			usage();
			exit(0);
		}
		if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		{
			puts("pg_tde_master_key (FortressQL) " PG_VERSION);
			exit(0);
		}
	}

	/* First non-option argument is the command */
	if (argc < 2)
	{
		pg_log_error("no command specified");
		pg_log_error_hint("Try \"%s --help\" for more information.", progname);
		exit(1);
	}

	command = argv[1];

	/* Shift argv so getopt processes options after the command */
	argc--;
	argv++;

	/* Reset optind for the shifted argv */
	optind = 1;

	while ((c = getopt_long(argc, argv, "D:fV?", long_options, NULL)) != -1)
	{
		switch (c)
		{
			case 'D':
				datadir = optarg;
				break;
			case 'f':
				force = true;
				break;
			case 'V':
				puts("pg_tde_master_key (FortressQL) " PG_VERSION);
				exit(0);
			default:
				/* getopt already emitted a complaint */
				pg_log_error_hint("Try \"%s --help\" for more information.", progname);
				exit(1);
		}
	}

	/* Fall back to PGDATA environment variable */
	if (datadir == NULL)
		datadir = getenv("PGDATA");

	if (datadir == NULL)
	{
		pg_log_error("no data directory specified");
		pg_log_error_hint("Try \"%s --help\" for more information.", progname);
		exit(1);
	}

#ifndef USE_PQC
	pg_log_error("FortressQL PQC support is not compiled in");
	pg_log_error_hint("Rebuild with -Dpqc=enabled and liboqs installed.");
	exit(1);
#endif

	/* Validate PGDATA exists and is a directory */
	{
		struct stat datadir_st;

		if (stat(datadir, &datadir_st) != 0)
		{
			pg_log_error("data directory \"%s\" does not exist: %m", datadir);
			exit(1);
		}
		if (!S_ISDIR(datadir_st.st_mode))
		{
			pg_log_error("\"%s\" is not a directory", datadir);
			exit(1);
		}
#ifndef WIN32
		/* Warn if PGDATA permissions are too permissive */
		if (datadir_st.st_mode & (S_IRWXG | S_IRWXO))
		{
			pg_log_warning("data directory \"%s\" has group or world access", datadir);
			pg_log_warning_hint("Recommended permissions are u=rwx (0700).");
		}
#endif
	}

	/* Dispatch command */
	if (strcmp(command, "init") == 0)
		ret = cmd_init(datadir, force);
	else if (strcmp(command, "rotate") == 0)
		ret = cmd_rotate(datadir);
	else if (strcmp(command, "export-pubkey") == 0)
		ret = cmd_export_pubkey(datadir);
	else if (strcmp(command, "info") == 0)
		ret = cmd_info(datadir);
	else
	{
		pg_log_error("unrecognized command \"%s\"", command);
		pg_log_error_hint("Try \"%s --help\" for more information.", progname);
		exit(1);
	}

	return ret;
}

#ifdef USE_PQC

/*
 * cmd_init
 *
 * Generate a new ML-KEM-768 keypair and write it to PGDATA.
 * Prints the hex-encoded secret key to stdout.
 */
static int
cmd_init(const char *datadir, bool force)
{
	PqcKemContext *ctx;
	char		keypath[MAXPGPATH];
	char	   *hex_sk;
	struct stat st;

	/* Check if master key already exists */
	snprintf(keypath, sizeof(keypath), "%s/%s", datadir, PQC_TDE_MASTER_KEY_FILE);
	if (stat(keypath, &st) == 0)
	{
		if (!force)
		{
			pg_log_error("master key already exists at \"%s\"", keypath);
			pg_log_error_hint("Use --force to overwrite, or \"%s rotate\" to rotate the master key.",
							  progname);
			return 1;
		}
		pg_log_warning("overwriting existing master key at \"%s\" (--force)",
					   keypath);
	}

	/* Initialize liboqs */
	OQS_init();

	/* Create KEM context */
	ctx = pqc_kem_ctx_new(PQC_TDE_KEM_ALGORITHM);
	if (ctx == NULL)
	{
		pg_log_error("failed to create KEM context for %s: "
					 "liboqs initialization may have failed", PQC_TDE_KEM_ALGORITHM);
		pg_log_error_hint("Ensure liboqs is properly installed and supports %s.",
						  PQC_TDE_KEM_ALGORITHM);
		OQS_destroy();
		return 1;
	}

	/* Generate keypair */
	if (pqc_kem_generate_keypair(ctx) != 0)
	{
		pg_log_error("failed to generate ML-KEM-768 keypair");
		pqc_kem_ctx_free(ctx);
		OQS_destroy();
		return 1;
	}

	/* Write master key files */
	if (write_master_key_files(datadir, ctx->public_key, ctx->public_key_len, 0) != 0)
	{
		OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
		pqc_kem_ctx_free(ctx);
		OQS_destroy();
		return 1;
	}

	/* Print secret key in hex */
	hex_sk = malloc(ctx->secret_key_len * 2 + 1);
	if (hex_sk == NULL)
	{
		pg_log_error("out of memory");
		/* Securely wipe secret key before freeing context */
		OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
		pqc_kem_ctx_free(ctx);
		OQS_destroy();
		return 1;
	}
	bytes_to_hex(ctx->secret_key, ctx->secret_key_len,
				 hex_sk, ctx->secret_key_len * 2 + 1);

	printf("Master key initialized successfully.\n");
	printf("Algorithm: %s\n", PQC_TDE_KEM_ALGORITHM);
	printf("Public key length: %zu bytes\n", ctx->public_key_len);
	printf("Secret key length: %zu bytes\n", ctx->secret_key_len);
	printf("\n");
	printf("KEM Secret Key (hex):\n");
	printf("%s\n", hex_sk);
	printf("\n");
	printf("IMPORTANT: Store the secret key securely. Set it as:\n");
	printf("  export FORTRESSQL_KEM_SECRET_KEY='%s'\n", hex_sk);

	/* Securely wipe secret key from memory */
	OQS_MEM_cleanse(hex_sk, ctx->secret_key_len * 2 + 1);
	free(hex_sk);
	OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
	pqc_kem_ctx_free(ctx);
	OQS_destroy();

	return 0;
}

/*
 * cmd_rotate
 *
 * Generate a new ML-KEM-768 keypair, replacing the existing one.
 * Prints the new hex-encoded secret key to stdout.
 */
static int
cmd_rotate(const char *datadir)
{
	PqcKemContext *ctx;
	char		keypath[MAXPGPATH];
	char	   *hex_sk;
	uint8_t    *old_data = NULL;
	size_t		old_len;
	PqcTdeMasterKeyHeader *old_hdr;
	uint32_t	rotation_count = 0;
	struct stat st;

	/* Verify existing master key exists */
	snprintf(keypath, sizeof(keypath), "%s/%s", datadir, PQC_TDE_MASTER_KEY_FILE);
	if (stat(keypath, &st) != 0)
	{
		pg_log_error("no existing master key found at \"%s\"", keypath);
		pg_log_error_hint("Use \"%s init\" to create a new master key.", progname);
		return 1;
	}

	/* Read the old key to get the rotation count */
	if (read_file_to_buf(keypath, &old_data, &old_len) == 0 &&
		old_len >= sizeof(PqcTdeMasterKeyHeader))
	{
		old_hdr = (PqcTdeMasterKeyHeader *) old_data;
		if (old_hdr->magic == PQC_TDE_KEY_MAGIC)
			rotation_count = old_hdr->rotation_count + 1;
	}
	if (old_data)
		free(old_data);

	/* Initialize liboqs */
	OQS_init();

	/* Create KEM context and generate new keypair */
	ctx = pqc_kem_ctx_new(PQC_TDE_KEM_ALGORITHM);
	if (ctx == NULL)
	{
		pg_log_error("failed to create KEM context for %s: "
					 "liboqs initialization may have failed", PQC_TDE_KEM_ALGORITHM);
		pg_log_error_hint("Ensure liboqs is properly installed and supports %s.",
						  PQC_TDE_KEM_ALGORITHM);
		OQS_destroy();
		return 1;
	}

	if (pqc_kem_generate_keypair(ctx) != 0)
	{
		pg_log_error("failed to generate ML-KEM-768 keypair");
		pqc_kem_ctx_free(ctx);
		OQS_destroy();
		return 1;
	}

	/* Overwrite master key files */
	if (write_master_key_files(datadir, ctx->public_key, ctx->public_key_len,
							   rotation_count) != 0)
	{
		OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
		pqc_kem_ctx_free(ctx);
		OQS_destroy();
		return 1;
	}

	/* Print new secret key in hex */
	hex_sk = malloc(ctx->secret_key_len * 2 + 1);
	if (hex_sk == NULL)
	{
		pg_log_error("out of memory");
		OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
		pqc_kem_ctx_free(ctx);
		OQS_destroy();
		return 1;
	}
	bytes_to_hex(ctx->secret_key, ctx->secret_key_len,
				 hex_sk, ctx->secret_key_len * 2 + 1);

	printf("Master key rotated successfully (rotation #%u).\n", rotation_count);
	printf("Algorithm: %s\n", PQC_TDE_KEM_ALGORITHM);
	printf("\n");
	printf("New KEM Secret Key (hex):\n");
	printf("%s\n", hex_sk);
	printf("\n");
	printf("IMPORTANT: Update the secret key in your configuration:\n");
	printf("  export FORTRESSQL_KEM_SECRET_KEY='%s'\n", hex_sk);

	OQS_MEM_cleanse(hex_sk, ctx->secret_key_len * 2 + 1);
	free(hex_sk);
	OQS_MEM_cleanse(ctx->secret_key, ctx->secret_key_len);
	pqc_kem_ctx_free(ctx);
	OQS_destroy();

	return 0;
}

/*
 * cmd_export_pubkey
 *
 * Read and export the public key from the master key file in hex.
 */
static int
cmd_export_pubkey(const char *datadir)
{
	char		keypath[MAXPGPATH];
	uint8_t    *data = NULL;
	size_t		data_len;
	PqcTdeMasterKeyHeader *hdr;
	uint8_t    *pubkey;
	char	   *hex_pk;

	snprintf(keypath, sizeof(keypath), "%s/%s", datadir, PQC_TDE_MASTER_KEY_FILE);

	if (read_file_to_buf(keypath, &data, &data_len) != 0)
	{
		pg_log_error("could not read master key file \"%s\"", keypath);
		return 1;
	}

	if (data_len < sizeof(PqcTdeMasterKeyHeader))
	{
		pg_log_error("master key file is too small");
		free(data);
		return 1;
	}

	hdr = (PqcTdeMasterKeyHeader *) data;
	if (hdr->magic != PQC_TDE_KEY_MAGIC)
	{
		pg_log_error("invalid master key file (bad magic)");
		free(data);
		return 1;
	}

	if (data_len < sizeof(PqcTdeMasterKeyHeader) + hdr->public_key_len)
	{
		pg_log_error("master key file is truncated");
		free(data);
		return 1;
	}

	pubkey = data + sizeof(PqcTdeMasterKeyHeader);

	hex_pk = malloc(hdr->public_key_len * 2 + 1);
	if (hex_pk == NULL)
	{
		pg_log_error("out of memory");
		free(data);
		return 1;
	}

	bytes_to_hex(pubkey, hdr->public_key_len,
				 hex_pk, hdr->public_key_len * 2 + 1);

	printf("%s\n", hex_pk);

	free(hex_pk);
	free(data);
	return 0;
}

/*
 * cmd_info
 *
 * Display information about the current master key.
 */
static int
cmd_info(const char *datadir)
{
	char		keypath[MAXPGPATH];
	uint8_t    *data = NULL;
	size_t		data_len;
	PqcTdeMasterKeyHeader *hdr;
	time_t		ctime;
	char		timebuf[128];

	snprintf(keypath, sizeof(keypath), "%s/%s", datadir, PQC_TDE_MASTER_KEY_FILE);

	if (read_file_to_buf(keypath, &data, &data_len) != 0)
	{
		pg_log_error("could not read master key file \"%s\"", keypath);
		pg_log_error_hint("Use \"%s init\" to create a new master key.", progname);
		return 1;
	}

	if (data_len < sizeof(PqcTdeMasterKeyHeader))
	{
		pg_log_error("master key file is too small");
		free(data);
		return 1;
	}

	hdr = (PqcTdeMasterKeyHeader *) data;
	if (hdr->magic != PQC_TDE_KEY_MAGIC)
	{
		pg_log_error("invalid master key file (bad magic)");
		free(data);
		return 1;
	}

	ctime = (time_t) hdr->creation_time;
	strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S UTC", gmtime(&ctime));

	printf("Master Key Information\n");
	printf("======================\n");
	printf("File:            %s\n", keypath);
	printf("Format version:  %u\n", hdr->version);
	printf("Algorithm:       %s\n", PQC_TDE_KEM_ALGORITHM);
	printf("Public key size: %u bytes\n", hdr->public_key_len);
	printf("Created:         %s\n", timebuf);
	printf("Rotation count:  %u\n", hdr->rotation_count);
	printf("Total file size: %zu bytes\n", data_len);

	free(data);
	return 0;
}

#else							/* !USE_PQC */

/* Stub implementations when PQC is not compiled in */
static int cmd_init(const char *datadir, bool force)
{
	pg_log_error("PQC support not compiled in");
	return 1;
}

static int cmd_rotate(const char *datadir)
{
	pg_log_error("PQC support not compiled in");
	return 1;
}

static int cmd_export_pubkey(const char *datadir)
{
	pg_log_error("PQC support not compiled in");
	return 1;
}

static int cmd_info(const char *datadir)
{
	pg_log_error("PQC support not compiled in");
	return 1;
}

#endif							/* USE_PQC */

/*
 * Helper: convert bytes to hex string.
 */
static void
bytes_to_hex(const uint8_t *data, size_t len, char *hex, size_t hex_len)
{
	static const char hexchars[] = "0123456789abcdef";
	size_t		i;

	if (hex_len < len * 2 + 1)
		return;

	for (i = 0; i < len; i++)
	{
		hex[i * 2] = hexchars[(data[i] >> 4) & 0x0F];
		hex[i * 2 + 1] = hexchars[data[i] & 0x0F];
	}
	hex[len * 2] = '\0';
}

/*
 * Helper: convert hex string to bytes.
 * Returns 0 on success, -1 on failure.
 */
static int
hex_to_bytes(const char *hex, uint8_t *data, size_t data_len)
{
	size_t		hex_len = strlen(hex);
	size_t		i;

	if (hex_len != data_len * 2)
		return -1;

	for (i = 0; i < data_len; i++)
	{
		unsigned int byte;

		if (sscanf(hex + i * 2, "%2x", &byte) != 1)
			return -1;
		data[i] = (uint8_t) byte;
	}

	return 0;
}

/*
 * Helper: ensure a directory exists, creating it if needed.
 */
static int
ensure_directory(const char *path)
{
	struct stat st;

	if (stat(path, &st) == 0)
	{
		if (S_ISDIR(st.st_mode))
			return 0;
		pg_log_error("\"%s\" exists but is not a directory", path);
		return -1;
	}

#ifdef WIN32
	if (mkdir(path) != 0)
#else
	if (mkdir(path, 0700) != 0)
#endif
	{
		pg_log_error("could not create directory \"%s\": %m", path);
		return -1;
	}

	return 0;
}

/*
 * Helper: write data to a file with secure permissions (0600).
 */
static int
write_secure_file(const char *path, const void *data, size_t len)
{
	int			fd;
	ssize_t		written;

#ifdef WIN32
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0600);
#else
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
#endif
	if (fd < 0)
	{
		pg_log_error("could not create file \"%s\": %m", path);
		return -1;
	}

	written = write(fd, data, len);
	if (written < 0 || (size_t) written != len)
	{
		pg_log_error("could not write to file \"%s\": %m", path);
		close(fd);
		return -1;
	}

	if (close(fd) != 0)
	{
		pg_log_error("could not close file \"%s\": %m", path);
		return -1;
	}

	return 0;
}

/*
 * Helper: read entire file into malloc'd buffer.
 */
static int
read_file_to_buf(const char *path, uint8_t **buf, size_t *len)
{
	FILE	   *fp;
	long		fsize;

	fp = fopen(path, "rb");
	if (fp == NULL)
		return -1;

	if (fseek(fp, 0, SEEK_END) != 0)
	{
		fclose(fp);
		return -1;
	}

	fsize = ftell(fp);
	if (fsize < 0)
	{
		fclose(fp);
		return -1;
	}

	if (fseek(fp, 0, SEEK_SET) != 0)
	{
		fclose(fp);
		return -1;
	}

	*buf = malloc((size_t) fsize);
	if (*buf == NULL)
	{
		fclose(fp);
		return -1;
	}

	if (fread(*buf, 1, (size_t) fsize, fp) != (size_t) fsize)
	{
		free(*buf);
		*buf = NULL;
		fclose(fp);
		return -1;
	}

	fclose(fp);
	*len = (size_t) fsize;
	return 0;
}

/*
 * Write the master key files to PGDATA/global/pg_encryption/.
 *
 * Creates the master.key file (header + public key) and a separate
 * master.pub file containing just the raw public key.
 */
static int
write_master_key_files(const char *datadir,
					   const uint8_t *public_key, size_t pk_len,
					   uint32_t rotation_count)
{
	char		dirpath[MAXPGPATH];
	char		globalpath[MAXPGPATH];
	char		keypath[MAXPGPATH];
	char		pubpath[MAXPGPATH];
	PqcTdeMasterKeyHeader hdr;
	uint8_t    *filebuf;
	size_t		filelen;

	/* Ensure global/ directory exists */
	snprintf(globalpath, sizeof(globalpath), "%s/global", datadir);
	if (ensure_directory(globalpath) != 0)
		return -1;

	/* Ensure global/pg_encryption/ directory exists */
	snprintf(dirpath, sizeof(dirpath), "%s/%s", datadir, PQC_TDE_ENCRYPTION_DIR);
	if (ensure_directory(dirpath) != 0)
		return -1;

	/* Build the header */
	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = PQC_TDE_KEY_MAGIC;
	hdr.version = PQC_TDE_KEY_VERSION;
	hdr.algorithm_id = 0;			/* ML-KEM-768 */
	hdr.public_key_len = (uint32_t) pk_len;
	hdr.creation_time = (uint32_t) time(NULL);
	hdr.rotation_count = rotation_count;

	/* Write master.key (header + public key) */
	filelen = sizeof(hdr) + pk_len;
	filebuf = malloc(filelen);
	if (filebuf == NULL)
	{
		pg_log_error("out of memory");
		return -1;
	}
	memcpy(filebuf, &hdr, sizeof(hdr));
	memcpy(filebuf + sizeof(hdr), public_key, pk_len);

	snprintf(keypath, sizeof(keypath), "%s/%s", datadir, PQC_TDE_MASTER_KEY_FILE);
	if (write_secure_file(keypath, filebuf, filelen) != 0)
	{
		free(filebuf);
		return -1;
	}
	free(filebuf);

	/* Write master.pub (raw public key) */
	snprintf(pubpath, sizeof(pubpath), "%s/%s", datadir, PQC_TDE_PUBLIC_KEY_FILE);
	if (write_secure_file(pubpath, public_key, pk_len) != 0)
		return -1;

	return 0;
}
