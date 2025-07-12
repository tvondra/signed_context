/*
 * signed_context.c - context signed using PKI
 *
 * Context is a list of key/value pairs, accessible by a session, stored
 * in a GUC variable. The values can be looked up by key, and used in
 * queries, RLS policies, etc.
 *
 * To make the context useful for RLS policies, the context needs to be
 * trusted against unauthorized modifications by non-authorized users.
 * This is achieved by protecting the context by PKI signatures, i.e.
 * the context can be initialized only if the value is signed by a key
 * known only to the privileged user. The signature can be verified
 * using a know public key, but the private key is stored elsewhere.
 *
 * The cryptography part (signing/verifying keys) is implemented by
 * libsodium.
 *
 * The context is managed as a regular GUC, which means it's subject to
 * RESET ALL. This is desirable for use in connection-pooling use cases,
 * where the context needs to be forgotten before handing over the
 * connection to someone else.
 *
 * Who initializes the context depends on the architecture and which
 * components are trusted. In can be either done by the connection poll
 * (or some other middleware component), before the connection is
 * handed over to the user/application. It may also be done by the
 * user, in which case it should only know it's own context (with a
 * valid signature).
 *
 * XXX The context cound be made settable only once, i.e. it would get
 * "sealed" and could not be changed even if the malicious user gets
 * access to a different token. But would be difficult to reset by the
 * connection pool.
 *
 * XXX There might be short expiration period, built into the context
 * value (the timestamp would be part of it), after which it'd not be
 * allowed to set. Requires a more automated workflow. Get a token, as
 * part of login into the system, pass it to the connection pool. This
 * idea reminds me the tickets in kerberos.
 *
 * XXX This relies on "public key" for verifying signatures. This must
 * be protected against changes by users, otherwise the user might set
 * the key to whatever, and then sign arbitrary contexts. PGC_SUSET
 * seems about right, and it allows per-database (or per-role) keys.
 *
 *
 * Copyright (C) Tomas Vondra, 2025
 */

#include <sodium.h>

#include "postgres.h"

#include "common/base64.h"
#include "funcapi.h"
#include "utils/builtins.h"
#include "utils/guc.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

/* the main context */
static char *signed_context_key = NULL;
static char *signed_context_string = NULL;

static bool signed_context_key_set = false;
static unsigned char signed_context_key_data[crypto_sign_PUBLICKEYBYTES];

/* prototypes */
PG_FUNCTION_INFO_V1(signed_context_get);
PG_FUNCTION_INFO_V1(signed_context_sign);
PG_FUNCTION_INFO_V1(signed_context_verify);
PG_FUNCTION_INFO_V1(signed_context_generate_keys);

Datum signed_context_get(PG_FUNCTION_ARGS);
Datum signed_context_sign(PG_FUNCTION_ARGS);
Datum signed_context_verify(PG_FUNCTION_ARGS);
Datum signed_context_generate_keys(PG_FUNCTION_ARGS);

static bool signed_context_key_check_hook(char **newval, void **extra, GucSource source);
static void signed_context_key_assign_hook(const char *newval, void *extra);
static const char *signed_context_key_show_hook(void);

static bool signed_context_str_check_hook(char **newval, void **extra, GucSource source);
static void signed_context_str_assign_hook(const char *newval, void *extra);
static const char *signed_context_str_show_hook(void);

static bool verify_signature(char *msg, char **payload);
static void context_add_entry(char *key, char *value);
static void context_free_entries(void);
static char *context_lookup_entry(char *key);


/*
 * Context represented by flexible array of key/value values, with all
 * values are strings. The context is stored in TopMemoryContext, it
 * would be better to have a separate memory context.
 *
 * XXX We expect only a handful of items
 */
typedef struct context_entry_t
{
	char   *key;
	char   *value;
} context_entry_t;

/* context with array resized to have enough space */
typedef struct context_t
{
	int		nentries;
	int		maxentries;
	context_entry_t *entries;
} context_t;

static context_t signed_context;

void
_PG_init(void)
{
	if (sodium_init() == -1)
		elog(ERROR, "failed to initialize libsodium");

	/*
	 * PGC_SIGHUP allows only one key in postgresql.conf, with PGC_SUSET we
	 * can have separate keys per database, etc. The risk is that if the
	 * user has privileged (superuser) role, he could set a key controls he
	 * controls.
	 * 
	 * XXX Maybe the GUC could be made as one-time-set, i.e. only the first
	 * set works, the following ones are ignored (i.e. once set, the key
	 * could not be changed).
	 */
	DefineCustomStringVariable("signed_context.key",
							   "Key used for verification of signed contexts.",
							   NULL,
							   &signed_context_key,
							   "",
							   PGC_SUSET,	/* see comment above */
							   0,
							   signed_context_key_check_hook,
							   signed_context_key_assign_hook,
							   signed_context_key_show_hook);

	DefineCustomStringVariable("signed_context.context",
							   "A string representing the current context contents.",
							   NULL,
							   &signed_context_string,
							   "",
							   PGC_USERSET,
							   0,
							   signed_context_str_check_hook,
							   signed_context_str_assign_hook,
							   signed_context_str_show_hook);

	/* empty context */
	signed_context.nentries = 0;
	signed_context.maxentries = 0;
	signed_context.entries = NULL;
}


/*
 * signed_context_get
 *		lookup value in the context
 *
 * Returns the value if key found, or NULL if key not in context.
 */
Datum
signed_context_get(PG_FUNCTION_ARGS)
{
	char   *key = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char   *value = context_lookup_entry(key);

	if (value)
		PG_RETURN_TEXT_P(cstring_to_text(value));

	PG_RETURN_NULL();
}

/*
 * signed_context_sign
 *		sign the provided context string, using the provided secret key
 *
 * Returns a string with the context, prefixed by the signature base64-encoded.
 * The context is used as-is, and there's a separator ':' after signature.
 *
 * Errors out if signature fails, which can happen for a number of reasons:
 *
 * - the key is invalid / doesn't have the expected length
 * - 
 */
Datum
signed_context_sign(PG_FUNCTION_ARGS)
{
	int		r;
	char   *key = text_to_cstring(PG_GETARG_TEXT_PP(0));
	char   *msg = text_to_cstring(PG_GETARG_TEXT_PP(1));
	char   *res,
		   *ptr;

	int					skeylen;
	unsigned char		skey[crypto_sign_SECRETKEYBYTES];

	unsigned long long	siglen;
	unsigned char		sig[crypto_sign_BYTES];

	unsigned long long	mlen = strlen(msg);	/* exclude terminator */

	/* secret key needs to be exactly crypto_sign_SECRETKEYBYTES bytes */
	skeylen = pg_b64_decode(key, strlen(key), skey, crypto_sign_SECRETKEYBYTES);
	if (skeylen != crypto_sign_SECRETKEYBYTES)
		elog(ERROR, "signature failed: invalid length of secret key");

	/*
	 * We want to base64-encode the signature, not the context, so got to
	 * use the detached mode.
	 */
	r = crypto_sign_detached((unsigned char *) sig, &siglen,
							 (unsigned char *) msg, mlen,
							 skey);

	if (r != 0)
		elog(ERROR, "signature failed: internal error");

	/*
	 * Let's build the output string, with base64 signature, ':' separator
	 * and the \0 terminator.
	 *
	 * XXX We don't know the exact base64 length, so use the upper bound
	 * for a signature of a given length.
	 */
	res = palloc0(pg_b64_enc_len(siglen) + mlen + 2);

	/* encode the signature into the output buffer */
	ptr = res;
	ptr += pg_b64_encode(sig, siglen, ptr, pg_b64_enc_len(siglen));

	/* pg_b64_encode() shouldn't return -1, the buffer is large enough */
	Assert(res < ptr);

	/* add the separator after signature */
	*ptr = ':';
	ptr++;

	/* and finally the original message, with a terminator */
	memcpy(ptr, msg, mlen);
	ptr += mlen;

	/* no underflows/overflows */
	Assert((res < ptr) && (ptr <= res + (pg_b64_enc_len(siglen) + mlen + 2)));

	PG_RETURN_TEXT_P(cstring_to_text((char *) res));
}

/*
 * signed_context_verify
 *		verify signature on a context
 *
 * Returns true if signature is valid, false otherwise.
 */
Datum
signed_context_verify(PG_FUNCTION_ARGS)
{
	char   *msg = text_to_cstring(PG_GETARG_TEXT_PP(0));
									
	PG_RETURN_BOOL(verify_signature(msg, NULL));
}

/*
 * helper to generate tuple descriptor for signed_context_generate_keys()
 */
static TupleDesc
signed_context_generate_keys_tupdesc(void)
{
	TupleDesc	tupdesc;

	tupdesc = CreateTemplateTupleDesc(2);
	TupleDescInitEntry(tupdesc, 1, "pkey", TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, 2, "skey", TEXTOID, -1, 0);

	return BlessTupleDesc(tupdesc);
}

/*
 * signed_context_generate_keys
 *		convenience function to generate random public/secret key pair
 *
 * The keys are generated using libsodium crypto_sign_keypair. The keys
 * are returned base64-encoded.
 */
Datum
signed_context_generate_keys(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Datum		values[2];
	bool		nulls[2];

	uint8 	pkey[crypto_sign_PUBLICKEYBYTES];
	uint8	skey[crypto_sign_SECRETKEYBYTES];

	int	pkey_len = pg_b64_enc_len(crypto_sign_PUBLICKEYBYTES);
	int	skey_len = pg_b64_enc_len(crypto_sign_SECRETKEYBYTES);

	/*
	 * Init to zero, to act as terminator (the base64 string could be shorter.
	 * Make sure to add 1 for terminator, if tbe base64 is full length.
	 */
	char  *pkey_enc = palloc0(pkey_len + 1);
	char  *skey_enc = palloc0(skey_len + 1);

	/* seems this only ever returns 0 */
	crypto_sign_keypair(pkey, skey);

	if (pg_b64_encode(pkey, crypto_sign_PUBLICKEYBYTES, pkey_enc, pkey_len) == -1)
		elog(ERROR, "failed encoding public key: too long");

	if (pg_b64_encode(skey, crypto_sign_SECRETKEYBYTES, skey_enc, skey_len) == -1)
		elog(ERROR, "failed encoding secret key: too long");

	tupdesc = signed_context_generate_keys_tupdesc();

	values[0] = PointerGetDatum(cstring_to_text(pkey_enc));
	values[1] = PointerGetDatum(cstring_to_text(skey_enc));

	nulls[0] = false;
	nulls[1] = false;

	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

/*
 * signed_context_key_check_hook
 *		check the public key when setting the GUC
 */
static bool
signed_context_key_check_hook(char **newval, void **extra, GucSource source)
{
	int				keylen;
	unsigned char  *key = NULL;

	/* no context value, means it's a reset - always allowed */
	if (strlen(*newval) == 0)
		return true;

	/* check the public key has the correct length */
	if (strlen(*newval) > pg_b64_enc_len(crypto_sign_PUBLICKEYBYTES))
	{
		GUC_check_errmsg("failed to set public key: key too long (%ld > %d)",
						 strlen(*newval), pg_b64_enc_len(crypto_sign_PUBLICKEYBYTES));
		return false;
	}

	/* decode the key */
	key = guc_malloc(LOG, crypto_sign_PUBLICKEYBYTES);
	if (!key)
	{
		GUC_check_errmsg("failed to allocate memory for key: OOM");
		return false;
	}

	/*
	 * Make sure we got exactly the right public key length (we know it
	 * should not be longer than crypto_sign_PUBLICKEYBYTES, thanks to
	 * the earlier check.
	 */
	keylen = pg_b64_decode(*newval, strlen(*newval), key, crypto_sign_PUBLICKEYBYTES);
	if (keylen == -1)
	{
		GUC_check_errmsg("failed to set public key: decoding failed");
		return false;
	}
	else if (keylen != crypto_sign_PUBLICKEYBYTES)
	{
		GUC_check_errmsg("failed to set public key: invalid key length");
		return false;
	}

	/* seems ok */
	*extra = key;

	return true;
}

/*
 * signed_context_key_assign_hook
 *		finish setting the public key, preprocessed by the check hook
 */
static void
signed_context_key_assign_hook(const char *newval, void *extra)
{
	if (strlen(newval) == 0)
	{
		/* paranoia: zero the current key */
		memset(signed_context_key_data, 0, crypto_sign_PUBLICKEYBYTES);
		signed_context_key_set = false;
		return;
	}

	/* copy the decoded value into the actual place */
	memcpy(signed_context_key_data, extra, crypto_sign_PUBLICKEYBYTES);
	signed_context_key_set = true;
}

/*
 * signed_context_key_show_hook
 *		simply show the (original) string representation of the key
 */
static const
char *signed_context_key_show_hook(void)
{
	return signed_context_key;
}

/* XXX probably should use strtok() */
static char **
signed_context_parse(char *str, int *nentries)
{
	int		cnt = 0;
	int		maxcnt = 0;
	char  **entries = NULL;
	char   *ptr,
		   *endptr;

	/* copy the payload, so that we can modify it while parsing */
	ptr = pstrdup(str);
	endptr = ptr + strlen(ptr);

	/* FIXME disallow zero-length keys */
	while (ptr < endptr)
	{
		char   *sep,
			   *key,
			   *value;

		/* make sure we have enough space for a key/value pair */
		if (cnt + 2 > maxcnt)
		{
			if (maxcnt == 0)
			{
				maxcnt = 8;
				entries = palloc(sizeof(char *) * maxcnt);
			}
			else
			{
				maxcnt *= 2;
				entries = repalloc(entries, sizeof(char *) * maxcnt);
			}
		}

		/* we have to have a separator after the key */
		sep = strchr(ptr, ':');
		if (sep == NULL)
		{
			elog(WARNING, "failed to parse key/value");
			return NULL;
		}

		/* terminate the key and move to the next character */
		key = ptr;
		*sep = '\0';
		ptr = ++sep;

		/*
		 * parse the value for the key, there may be a separator, but if
		 * there's not one use the rest of the string
		 */
		sep = strchr(ptr, ':');
		if (sep != NULL)
			*sep = '\0';

		value = ptr;

		/* move to the next character after the terminated value */
		ptr += strlen(value) + 1;

		entries[cnt++] = key;
		entries[cnt++] = value;
	}

	*nentries = cnt;
	return entries;
}

/*
 * signed_context_str_check_hook
 *		check the context we're about to set into the GUC
 */
static bool
signed_context_str_check_hook(char **newval, void **extra, GucSource source)
{
	int		nvalues;
	char  **values;
	char   *msg,
		   *payload;

	/* setting to empty string means resetting, always allow */
	if (strlen(*newval) == 0)
		return true;

	/*
	 * Extract the payload string (this verifies the signature and errors
	 * out if the signature is wrong).
	 */
	msg = (char *) *newval;
	if (!verify_signature(msg, &payload))
	{
		GUC_check_errmsg("invalid signature");
		return false;
	}

	values = signed_context_parse(payload, &nvalues);
	if (values == NULL)
	{
		GUC_check_errmsg("failed to parse context");
		return false;
	}

	return true;
}

/*
 * signed_context_str_check_hook
 *		check the context we're about to set into the GUC
 *
 * XXXX should verify signature and do most of the parsing (move it from
 * the assign hook)
 *
 * XXX Should verify the format of the context key/value part, we might fail
 * after already forgetting the current context.
 */
static void
signed_context_str_assign_hook(const char *newval, void *extra)
{
	int		nvalues;
	char  **values;
	char   *payload,
		   *msg;

	/* setting to empty string means resetting, always allow */
	if (strlen(newval) == 0)
	{
		context_free_entries();
		return;
	}

	/*
	 * Extract the payload string (this verifies the signature and errors
	 * out if the signature is wrong).
	 */
	msg = (char *) newval;
	if (!verify_signature(msg, &payload))
	{
		/* should not happen, thanks to the check hook */
		Assert(false);
	}

	values = signed_context_parse(payload, &nvalues);

	/* should not happen, thanks to the check hook */
	Assert(values != NULL);
	Assert(nvalues % 2 == 0);	/* key/value pairs */

	context_free_entries();

	for (int i = 0; i < nvalues; i += 2)
	{
		context_add_entry(values[i], values[i+1]);
	}
}

/*
 * signed_context_str_show_hook
 *		format the current context as key/value pairs
 */
static const
char *signed_context_str_show_hook(void)
{
	StringInfoData str;

	initStringInfo(&str);

	for (int i = 0; i < signed_context.nentries; i++)
	{
		if (i > 0)
			appendStringInfoChar(&str, ':');

		appendStringInfo(&str, "%s:%s",
						 signed_context.entries[i].key,
						 signed_context.entries[i].value);
	}

	return str.data;
}

/*
 * verify_signature
 *		verify signature of a message
 *
 * Splits the message on the first ':' into signature:context, and then
 * verify the signature using the current public key.
 *
 * Returns true if signature is valid, false otherwise (in this case payload
 * is set to NULL). (Does not throw any errors, so that it can be used in GUC
 * check hooks.)
 */
static bool
verify_signature(char *msg, char **payload)
{
	int		r;
	char   *sep = strchr(msg, ':');

	unsigned long long	mlen;
	unsigned char		sig[crypto_sign_BYTES];

	/* make sure we don't return bogus payloads */
	if (payload != NULL)
		*payload = NULL;

	/* can't do anything without the key */
	if (!signed_context_key_set)
	{
		elog(WARNING, "public key is not initialized");
		return false;
	}

	/* the signature needs to be present, and not too long */
	if (sep == NULL)
	{
		elog(WARNING, "invalid format: missing separator ':'");
		return false;
	}
	else if ((sep - msg) > pg_b64_enc_len(crypto_sign_BYTES))
	{
		elog(WARNING, "invalid format: signature too long");
		return false;
	}

	/* decode the signature part (it can be shorter) */
	if (pg_b64_decode(msg, (sep - msg), sig, crypto_sign_BYTES) == -1)
	{
		elog(WARNING, "failed to decode signature (invalid length or not valid base64)");
		return false;
	}

	/* message starts after the signature and separator */
	msg = (sep + 1);
	mlen = strlen(msg);

	r = crypto_sign_verify_detached(sig, (unsigned char *) msg, mlen,
									signed_context_key_data);

	if ((r == 0) && (payload != NULL))
		*payload = (++sep);

	return (r == 0);
}

/*
 * context_free_entries
 *		discard current entries in signed_context (if any)
 */
static void
context_free_entries(void)
{
	for (int i = 0; i < signed_context.nentries; i++)
	{
		pfree(signed_context.entries[i].key);
		pfree(signed_context.entries[i].value);
	}

	signed_context.nentries = 0;
}

/*
 * context_add_entry
 *		add key/value entry to the current context, expanding it if needed
 *
 * XXX Should probably allow only sensible lengths. Should check the keys
 * are unique, and that theare not too many of them (for linear search).
 */
static void
context_add_entry(char *key, char *value)
{
	/* XXX bleah: should not use TopMemoryContext directly */
	MemoryContext oldcxt = MemoryContextSwitchTo(TopMemoryContext);

	/* expand the array if all entries used */
	if (signed_context.nentries == signed_context.maxentries)
	{
		if (signed_context.maxentries == 0)
		{
			signed_context.maxentries = 16;
			signed_context.entries
				= palloc(sizeof(context_entry_t) * signed_context.maxentries);
		}
		else
		{
			signed_context.maxentries *= 2;
			signed_context.entries
				= repalloc(signed_context.entries,
						   sizeof(context_entry_t) * signed_context.maxentries);
		}
	}

	signed_context.entries[signed_context.nentries].key = pstrdup(key);
	signed_context.entries[signed_context.nentries].value = pstrdup(value);

	MemoryContextSwitchTo(oldcxt);

	signed_context.nentries++;
}

/*
 * context_lookup_entry
 *		lookup entry in the context using linear search
 *
 * Returns the value if key found, NULL otherwise.
 */
static char *
context_lookup_entry(char *key)
{
	char *value = NULL;

	for (int i = 0; i < signed_context.nentries; i++)
	{
		if (strcmp(signed_context.entries[i].key, key) == 0)
		{
			value = signed_context.entries[i].value;
			break;
		}
	}

	return value;
}
